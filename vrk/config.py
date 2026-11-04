import ipaddress
import re
from .util import Error

PROTOCOLS = {"vision", "xhttp", "hysteria2"}
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")


def require(ok, message):
    if not ok:
        raise Error(message)


def name(value):
    require(isinstance(value, str) and bool(NAME.fullmatch(value)), "invalid identifier")
    return value


def address(value):
    require(
        isinstance(value, str)
        and bool(value)
        and len(value) < 254
        and not any(c in value for c in "\n\r\t /;\"'"),
        "invalid address",
    )
    try:
        require(
            isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address),
            "v1 addresses use IPv4 or hostnames",
        )
    except ValueError:
        require(bool(re.fullmatch(r"[A-Za-z0-9.-]+", value)), "invalid hostname")
    return value


def port(value):
    require(type(value) is int and 1 <= value <= 65535, "invalid port")
    return value


def validate(c):
    require(isinstance(c, dict), "configuration must be an object")
    require(isinstance(c.get("listeners"), list), "listeners must be an array")
    require(isinstance(c.get("relays", []), list), "relays must be an array")
    require(bool(c["listeners"] or c.get("relays")), "at least one listener or relay is required")
    require(all(isinstance(l, dict) for l in c["listeners"]), "listener must be an object")
    require(isinstance(c.get("routing"), dict), "routing must be an object")
    require(
        not (
            set(c)
            - {
                "schema_version",
                "address",
                "listeners",
                "nodes",
                "routing",
                "relays",
                "manage_firewall",
                "_bindings",
            }
        ),
        "unknown top-level configuration key",
    )
    require(c.get("schema_version") == 1, "schema_version must be 1")
    address(c.get("address"))
    require(type(c.get("manage_firewall", False)) is bool, "manage_firewall must be boolean")
    nodes = c.get("nodes", {})
    require(isinstance(nodes, dict), "nodes must be an object")
    for key, n in nodes.items():
        require(isinstance(n, dict), "node must be an object")
        name(key)
        require(
            not (
                set(n)
                - {
                    "protocol",
                    "address",
                    "port",
                    "secret",
                    "server_name",
                    "public_key",
                    "short_id",
                    "path",
                }
            ),
            "unknown node key",
        )
        require(n.get("protocol") in PROTOCOLS, "unsupported node protocol")
        address(n.get("address"))
        port(n.get("port"))
        name(n.get("secret"))
        address(n.get("server_name"))
        if n["protocol"] != "hysteria2":
            require(
                bool(re.fullmatch(r"[A-Za-z0-9_-]{43}", n.get("public_key", ""))),
                "invalid REALITY public key",
            )
            require(
                bool(re.fullmatch(r"(?:[a-fA-F0-9]{2}){0,8}", n.get("short_id", ""))),
                "invalid short_id",
            )
        if n["protocol"] == "xhttp":
            require(str(n.get("path", "")).startswith("/"), "xhttp path must start with /")
        require("via" not in n, "node chains belong in explicit relays, not recursive via settings")
    used = set()
    ids = set()
    require(
        sum(l.get("certificate", {}).get("mode") == "acme" for l in c.get("listeners", [])) <= 1,
        "one ACME HTTP-01 listener per host; use certificate files for additional listeners",
    )

    def bind(proto, host, p):
        require(
            isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address),
            "v1 listeners use IPv4 only",
        )
        port(p)
        require(
            not any(
                t == proto
                and pp == p
                and (h == host or h in ("0.0.0.0", "::") or host in ("0.0.0.0", "::"))
                for t, h, pp in used
            ),
            "duplicate or overlapping listener",
        )
        used.add((proto, host, p))

    for l in c.get("listeners", []):
        require(
            not (
                set(l)
                - {
                    "id",
                    "protocol",
                    "listen",
                    "port",
                    "secret",
                    "server_name",
                    "target",
                    "target_port",
                    "path",
                    "certificate",
                }
            ),
            "unknown listener key",
        )
        name(l.get("id"))
        require(
            l["id"] != "hy-bridge" and not l["id"].startswith("client-"), "reserved listener id"
        )
        require(l["id"] not in ids, "duplicate listener id")
        ids.add(l["id"])
        require(l.get("protocol") in PROTOCOLS, "unsupported listener protocol")
        name(l.get("secret"))
        host = l.get("listen", "0.0.0.0")
        bind("udp" if l["protocol"] == "hysteria2" else "tcp", host, l.get("port"))
        if l["protocol"] != "hysteria2":
            address(l.get("server_name"))
            address(l.get("target"))
            port(l.get("target_port", 443))
            if l["protocol"] == "xhttp":
                require(str(l.get("path", "")).startswith("/"), "xhttp path must start with /")
        else:
            cert = l.get("certificate", {})
            require(cert.get("mode") in ("acme", "files"), "certificate mode must be acme/files")
            address(l.get("server_name"))
            if cert["mode"] == "acme":
                require("@" in cert.get("email", ""), "ACME email required")
            else:
                for k in ("cert", "key"):
                    require(
                        str(cert.get(k, "")).startswith("/"), "certificate paths must be absolute"
                    )
    for relay in c.get("relays", []):
        name(relay.get("id"))
        require(relay["id"] not in ids, "duplicate resource id")
        ids.add(relay["id"])
        address(relay.get("remote"))
        port(relay.get("remote_port"))
        transports = relay.get("transports", ["tcp"])
        require(transports and set(transports) <= {"tcp", "udp"}, "invalid relay transports")
        for t in transports:
            bind(t, relay.get("listen", "0.0.0.0"), relay.get("port"))
        require(
            not (relay["remote"] == c["address"] and relay["remote_port"] == relay["port"]),
            "relay loop",
        )
    routing = c.get("routing", {})
    require(not (set(routing) - {"default", "rules"}), "unknown routing key")

    def action(a):
        require(
            a in ("local", "reject")
            or (isinstance(a, str) and a.startswith("node:") and a[5:] in nodes),
            "unknown routing action/node",
        )

    action(routing.get("default"))
    require(isinstance(routing.get("rules", []), list), "rules must be an array")
    for rule in routing.get("rules", []):
        require(isinstance(rule, dict), "rule must be an object")
        require(set(rule) <= {"domain", "suffix", "cidr", "action"}, "unknown routing rule key")
        require(
            sum(bool(rule.get(k)) for k in ("domain", "suffix", "cidr")) == 1,
            "each rule must use one match type",
        )
        action(rule.get("action"))
        for k in ("domain", "suffix", "cidr"):
            require(isinstance(rule.get(k, []), list), "rule matches must be arrays")
            for v in rule.get(k, []):
                if k == "cidr":
                    ipaddress.ip_network(v, strict=False)
                else:
                    address(v)
    # Internal bridge ports are fixed, declared, and included in conflict checks.
    from .render import bridge_required

    if bridge_required(c):
        bind("tcp", "127.0.0.1", 18080)
        bind("udp", "127.0.0.1", 18080)
    for i, key in enumerate(sorted(referenced_nodes(c))):
        if nodes[key]["protocol"] == "hysteria2":
            bind("tcp", "127.0.0.1", 18100 + i)
    for key in referenced_nodes(c):
        n = nodes[key]
        require(
            not (
                n["address"] in (c["address"], "127.0.0.1", "localhost")
                and any(l["port"] == n["port"] for l in c["listeners"])
            ),
            "node points back to a local listener",
        )
    c["_bindings"] = [list(b) for b in sorted(used)]
    return c


def referenced_nodes(c):
    r = c.get("routing", {})
    return {
        a[5:]
        for a in [r.get("default", "")] + [x.get("action", "") for x in r.get("rules", [])]
        if a.startswith("node:")
    }


def sample():
    return {
        "schema_version": 1,
        "address": "203.0.113.10",
        "listeners": [
            {
                "id": "vision",
                "protocol": "vision",
                "listen": "0.0.0.0",
                "port": 24443,
                "secret": "primary",
                "server_name": "www.example.com",
                "target": "www.example.com",
            },
            {
                "id": "xhttp",
                "protocol": "xhttp",
                "listen": "0.0.0.0",
                "port": 25443,
                "secret": "primary",
                "server_name": "www.example.com",
                "target": "www.example.com",
                "path": "/vrk",
            },
            {
                "id": "hy2",
                "protocol": "hysteria2",
                "listen": "0.0.0.0",
                "port": 24443,
                "secret": "hy2",
                "server_name": "hy2.example.com",
                "certificate": {"mode": "acme", "email": "admin@example.com"},
            },
        ],
        "nodes": {},
        "routing": {"default": "local", "rules": []},
        "relays": [],
    }
