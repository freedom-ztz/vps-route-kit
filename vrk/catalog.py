"""Private route inventory; public reports contain identities, never node credentials."""

import copy
import ipaddress
import re
from pathlib import Path
from .config import address, name, port
from .util import Error, digest, encode, read


def require(ok, message):
    if not ok:
        raise Error(message)


def validate(c):
    require(isinstance(c, dict) and c.get("schema_version") == 1, "invalid catalog version")
    require(
        set(c)
        <= {"schema_version", "hosts", "nodes", "routes", "dns", "company", "rules", "local"},
        "unknown catalog field",
    )
    hosts, nodes, routes = c.get("hosts"), c.get("nodes"), c.get("routes")
    require(isinstance(hosts, dict) and bool(hosts), "hosts must be a nonempty object")
    require(isinstance(nodes, dict) and bool(nodes), "nodes must be a nonempty object")
    require(isinstance(routes, list) and bool(routes), "routes must be a nonempty array")
    for key, h in hosts.items():
        name(key)
        require(isinstance(h, dict) and set(h) <= {"address", "ssh", "jump"}, "invalid host")
        address(h.get("address"))
        for field in ("ssh", "jump"):
            if field in h:
                require(
                    bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", h[field])),
                    "invalid SSH host",
                )
    for key, n in nodes.items():
        name(key)
        require(
            isinstance(n, dict) and n.get("type") in ("vless", "hysteria2"),
            "unsupported catalog node",
        )
        address(n.get("server"))
        port(n.get("port"))
        require(
            n.get("skip-cert-verify", False) is False,
            "certificate verification must remain enabled",
        )
        if n["type"] == "vless":
            require(
                n.get("tls") is True and bool(n.get("uuid")) and bool(n.get("reality-opts")),
                "VLESS requires REALITY credentials",
            )
            require(n.get("network", "tcp") in ("tcp", "xhttp"), "unsupported VLESS transport")
        else:
            require(
                bool(n.get("password")) and bool(n.get("sni")), "Hysteria credentials/SNI required"
            )
        if "dialer-proxy" in n:
            require(
                n["dialer-proxy"] in nodes and n["dialer-proxy"] != key, "invalid carrier reference"
            )

    def visit(key, stack):
        require(key not in stack, "carrier cycle")
        if nodes[key].get("dialer-proxy"):
            visit(nodes[key]["dialer-proxy"], stack | {key})

    for key in nodes:
        visit(key, set())
    seen = set()
    for r in routes:
        require(
            isinstance(r, dict)
            and set(r)
            <= {
                "id",
                "node",
                "path",
                "exit_host",
                "exit_country",
                "expected_exit_ipv4",
                "acceptance",
                "display_name",
                "priority",
            },
            "invalid route fields",
        )
        name(r.get("id"))
        require(r["id"] not in seen, "duplicate route id")
        seen.add(r["id"])
        require(
            type(r.get("priority", 100)) is int and 0 <= r.get("priority", 100) <= 10000,
            "route priority must be an integer from 0 to 10000",
        )
        if "display_name" in r:
            label = r["display_name"]
            require(
                isinstance(label, str)
                and 1 <= len(label) <= 80
                and label.strip() == label
                and not any(ord(ch) < 32 or ord(ch) == 127 for ch in label)
                and label
                not in {
                    "DIRECT",
                    "REJECT",
                    "COMPATIBLE",
                    "GLOBAL",
                    "PASS",
                    "REJECT-DROP",
                    "外网",
                    "自动",
                    "手动",
                    "测试",
                }
                and not label.startswith(("_carrier-", "_vrk-hop-")),
                "invalid route display_name",
            )
        require(r.get("node") in nodes, "unknown route node")
        path = r.get("path")
        require(
            isinstance(path, list) and bool(path) and all(h in hosts for h in path),
            "unknown path host",
        )
        require(len(set(path)) == len(path), "route path cycle")
        require(r.get("exit_host") == path[-1], "exit_host must end the path")
        require(
            r.get("exit_country") in ("SG", "JP", "US", "HK"),
            "supported exits are SG/JP/US and manual-only HK",
        )
        require(
            isinstance(ipaddress.ip_address(r.get("expected_exit_ipv4")), ipaddress.IPv4Address),
            "IPv4 exit required",
        )
    dns = c.get("dns", {})
    require(
        isinstance(dns, dict) and set(dns) <= {"bootstrap", "domestic", "remote"},
        "invalid DNS config",
    )
    for field in ("bootstrap", "domestic", "remote"):
        if field in dns:
            require(
                isinstance(dns[field], list)
                and dns[field]
                and all(isinstance(v, str) and v for v in dns[field]),
                "invalid DNS server list",
            )
    company = c.get("company", {})
    require(
        isinstance(company, dict) and set(company) <= {"domains", "cidrs", "dns"},
        "invalid company config",
    )
    for d in company.get("domains", []):
        address(d)
    for cidr in company.get("cidrs", []):
        require(ipaddress.ip_network(cidr, strict=False).version == 4, "IPv4 company CIDR required")
    if company.get("domains"):
        require(
            isinstance(company.get("dns"), list) and bool(company["dns"]), "company DNS required"
        )
    return c


def fingerprint(c, r):
    nodes = {}
    key = r["node"]
    while key not in nodes:
        nodes[key] = c["nodes"][key]
        key = nodes[key].get("dialer-proxy")
        if not key:
            break
    return digest(
        encode(
            {
                "route": {
                    k: v
                    for k, v in r.items()
                    if k not in {"acceptance", "display_name", "priority"}
                },
                "hosts": {k: c["hosts"][k] for k in r["path"]},
                "nodes": nodes,
            }
        )
    )


def binding(c, r, targets, batch_id, core_versions):
    require(isinstance(batch_id, str) and bool(batch_id), "evidence batch_id required")
    require(
        isinstance(core_versions, dict)
        and bool(core_versions)
        and all(isinstance(v, str) and v for v in core_versions.values()),
        "evidence core_versions required",
    )
    return {
        "fingerprint": fingerprint(c, r),
        "batch_id": batch_id,
        "core_versions": core_versions,
        "targets_sha256": digest(encode(targets)),
    }


def accepted(c, r, base):
    """Require separate matching egress and completed stability receipts."""
    try:
        refs = r.get("acceptance", {})
        d = read(Path(base) / refs["diagnosis"])
        s = read(Path(base) / refs["stability"])
        evidence = d["routes"][r["id"]]
        cases = [v for k, v in s["cases"].items() if k.startswith(r["id"] + "/")]
        bound = evidence.get("binding", {})
        exercises = evidence.get("exercises", {})
        required = {"stream", "idle", "download", "upload"}
        if c["nodes"][r["node"]].get("udp", True):
            required.add("udp")
        if not isinstance(exercises, dict) or not all(
            isinstance(exercises.get(k), dict) and exercises[k].get("ok") is True for k in required
        ):
            return False
        return (
            d.get("completed") is True
            and bool(bound.get("batch_id"))
            and bool(bound.get("core_versions"))
            and bool(bound.get("targets_sha256"))
            and bound == s.get("bindings", {}).get(r["id"])
            and bound.get("fingerprint") == fingerprint(c, r)
            and evidence["fingerprint"] == fingerprint(c, r)
            and evidence["ok"] is True
            and evidence["exit_ipv4"] == r["expected_exit_ipv4"]
            and s.get("completed") is True
            and s.get("elapsed_seconds", 0) >= 1800
            and len(cases) >= 2
            and all(v["checks"] >= 60 and v["failures"] == 0 for v in cases)
        )
    except (OSError, KeyError, ValueError, TypeError):
        return False


def report(c, base=".", previous=None):
    validate(c)
    dependencies = {}
    for r in c["routes"]:
        for h in r["path"]:
            dependencies.setdefault(h, []).append(r["id"])
    routes = [
        {
            "id": r["id"],
            "protocol": c["nodes"][r["node"]]["type"],
            "exit_country": r["exit_country"],
            "path": r["path"],
            "accepted": accepted(c, r, base),
            "fingerprint": fingerprint(c, r),
        }
        for r in c["routes"]
    ]
    result = {
        "routes": routes,
        "shared_dependencies": {h: ids for h, ids in dependencies.items() if len(ids) > 1},
        "redundancy_note": "Shared landing hosts provide entry-path redundancy, not independent server redundancy.",
    }
    if previous:
        old = {r["id"]: r for r in previous.get("routes", [])}
        now = {r["id"]: r for r in routes}
        result["changes"] = {
            "added": sorted(now.keys() - old.keys()),
            "removed": sorted(old.keys() - now.keys()),
            "changed": sorted(k for k in old.keys() & now.keys() if old[k] != now[k]),
        }
    return result


def selected(c, base, candidates=False):
    validate(c)
    routes = [r for r in c["routes"] if candidates or accepted(c, r, base)]
    require(bool(routes), "no accepted routes; use --include-candidates only for isolated tests")
    return sorted(
        routes,
        key=lambda r: (
            ("SG", "JP", "US", "HK").index(r["exit_country"]),
            r.get("priority", 100),
            len(r["path"]),
            r["id"],
        ),
    )


def proxies(c, routes):
    output = {}

    def carrier(key):
        alias = "_carrier-" + key
        if alias not in output:
            n = copy.deepcopy(c["nodes"][key])
            n["name"] = alias
            if n.get("dialer-proxy"):
                n["dialer-proxy"] = carrier(n["dialer-proxy"])
            output[alias] = n
        return alias

    names = []
    for r in routes:
        n = copy.deepcopy(c["nodes"][r["node"]])
        n["name"] = r.get("display_name", r["exit_country"] + "-" + r["id"])
        require(n["name"] not in output, "duplicate exported node name")
        if n.get("dialer-proxy"):
            n["dialer-proxy"] = carrier(n["dialer-proxy"])
        output[n["name"]] = n
        names.append(n["name"])
    return list(output.values()), names
