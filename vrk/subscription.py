"""Build private static subscriptions. No HTTP daemon or runtime policy generator."""

import base64
import copy
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import urllib.parse
import urllib.request
from . import catalog
from .util import Error, atomic, digest, encode, read, run

HEALTH = {
    "url": "https://www.gstatic.com/generate_204",
    "interval": 60,
    "timeout": 8000,
    "lazy": False,
    "expected-status": 204,
}
FILES = (
    "nodes.json",
    "desktop.json",
    "v2ray.txt",
    "openwrt-example.json",
    "manifest.json",
    "rules/domains.txt",
    "rules/cidrs.txt",
)


def locked_rule(spec, kind):
    if not isinstance(spec, dict) or set(spec) != {"url", "sha256"}:
        raise Error("rule source requires url and sha256")
    u = urllib.parse.urlsplit(spec["url"])
    if (
        u.scheme != "https"
        or u.username
        or u.password
        or not re.fullmatch("[a-f0-9]{64}", spec["sha256"])
    ):
        raise Error("rules require HTTPS and locked SHA-256")
    with urllib.request.urlopen(spec["url"], timeout=30) as response:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise Error("rule redirect must remain HTTPS")
        data = response.read(16_000_001)
    if len(data) > 16_000_000 or digest(data) != spec["sha256"]:
        raise Error("rule size/checksum mismatch; previous release unchanged")
    lines = []
    for line in data.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if kind == "domains":
            domain = line.removeprefix("+.").removeprefix(".")
            catalog.address(domain)
        else:
            if ipaddress.ip_network(line, strict=False).version != 4:
                continue
        lines.append(line)
    if not lines:
        raise Error("empty domestic rules rejected")
    return "\n".join(dict.fromkeys(lines)) + "\n"


def origin_url(value):
    u = urllib.parse.urlsplit(value)
    if (
        u.scheme != "https"
        or not u.hostname
        or u.username
        or u.password
        or u.query
        or u.fragment
        or u.path not in ("", "/")
    ):
        raise Error("base-url must be an HTTPS origin, without credentials/path/query")
    return value.rstrip("/")


def access(path, rotate=False):
    if path is None:
        raise Error("token access requires --access-file")
    path = Path(path)
    if path.is_symlink():
        raise Error("access file must not be a symlink")
    if path.exists():
        path.chmod(0o600)
    if path.exists() and not rotate:
        value = read(path)
    else:
        value = {"token": secrets.token_urlsafe(32)}
        atomic(path, value)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value.get("token", "")):
        raise Error("invalid subscription token")
    return value["token"]


def groups(names, provider=None):
    # Mihomo uses the first member when none are healthy.
    fallback = {"name": "自动", "type": "fallback", **HEALTH, "proxies": ["REJECT"] + list(names)}
    manual = {"name": "手动", "type": "select", "proxies": list(names) + ["REJECT"]}
    if provider:
        for g in (fallback, manual):
            g["use"] = [provider]
            g["filter"] = "^(SG|JP|US)-"
    return [{"name": "外网", "type": "select", "proxies": ["自动", "手动"]}, fallback, manual]


def build(
    c,
    base,
    output,
    base_url,
    access_file,
    mihomo,
    candidates=False,
    *,
    name="builder",
    formats="clash,v2ray",
    access_mode="token",
):
    catalog.validate(c)
    catalog.name(name)
    formats = formats.split(",") if isinstance(formats, str) else list(formats)
    if not formats or len(set(formats)) != len(formats) or set(formats) - {"clash", "v2ray"}:
        raise Error("formats must select clash and/or v2ray")
    if access_mode not in ("public", "token"):
        raise Error("invalid access mode")
    if access_mode == "public" and c.get("company"):
        raise Error("public subscriptions cannot include company configuration")
    output = Path(output)
    if output.exists():
        raise Error("build output exists; choose a new release directory")
    url = origin_url(base_url)
    if access_mode == "token":
        if not access_file:
            raise Error("token mode requires --access-file")
        url += "/" + access(access_file)
    routes = catalog.selected(c, base, candidates)
    nodes, names = catalog.proxies(c, routes)
    from .export import mihomo_uri

    shareable = [n for n in nodes if n["name"] in names and not n.get("dialer-proxy")]
    if "v2ray" in formats and not shareable:
        raise Error(
            "no V2Ray-shareable routes; client chains require Clash groups, use transparent server-side relays or separate routes"
        )
    v2ray = base64.b64encode("".join(mihomo_uri(n) for n in shareable).encode()).decode() + "\n"
    lock = c.get("rules") or read(Path(__file__).with_name("rules.lock.json"))
    if set(lock) != {"domains", "cidrs"}:
        raise Error("domestic domain and CIDR locks required")
    rules = {k: locked_rule(lock[k], k) for k in ("domains", "cidrs")} if "clash" in formats else {}
    dns = {
        "bootstrap": ["223.5.5.5", "119.29.29.29"],
        "domestic": ["https://dns.alidns.com/dns-query"],
        "remote": ["https://1.1.1.1/dns-query#外网"],
        **c.get("dns", {}),
    }
    company = c.get("company", {})
    local = c.get("local", {})
    if local and (set(local) != {"domains", "dns"} or not local["domains"] or not local["dns"]):
        raise Error("local requires domains and DNS")
    # Health-probe DNS must not depend on the group being tested.
    policy = {
        "rule-set:domestic-domains": dns["domestic"],
        urllib.parse.urlsplit(HEALTH["url"]).hostname: dns["domestic"],
    }
    for d in local.get("domains", []):
        catalog.address(d)
        policy["+." + d] = local["dns"]
    for d in company.get("domains", []):
        policy["+." + d] = company["dns"]
    rule_version = digest(encode(rules))[:20]
    rule_base = url + "/rules/" + rule_version if access_mode == "public" else url + "/rules"
    providers = {
        f"domestic-{k}": {
            "type": "http",
            "behavior": "domain" if k == "domains" else "ipcidr",
            "format": "text",
            "url": f"{rule_base}/{k}.txt",
            "path": f"./rules/vrk-{k}.txt",
            "interval": 86400,
            "proxy": "外网",
        }
        for k in rules
    }
    direct = [
        "DOMAIN-SUFFIX,lan,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    ]
    desktop = {
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "mixed-port": 7890,
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "tun": {"enable": False},
        "proxies": nodes,
        "proxy-groups": groups(names),
        "rule-providers": providers,
        "dns": {
            "enable": True,
            "listen": "127.0.0.1:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-filter": ["*.lan", "*.local"]
            + ["+." + d for d in company.get("domains", []) + local.get("domains", [])],
            "default-nameserver": dns["bootstrap"],
            "proxy-server-nameserver": dns["domestic"],
            "nameserver-policy": policy,
            "nameserver": dns["remote"],
        },
        "rules": [
            "DOMAIN-SUFFIX," + d + ",DIRECT"
            for d in company.get("domains", []) + local.get("domains", [])
        ]
        + ["IP-CIDR," + d + ",DIRECT,no-resolve" for d in company.get("cidrs", [])]
        + direct
        + [
            "RULE-SET,domestic-domains,DIRECT",
            "RULE-SET,domestic-cidrs,DIRECT,no-resolve",
            "MATCH,外网",
        ],
    }
    example = {
        "proxy-providers": {
            "vrk": {
                "type": "http",
                "proxy": "DIRECT",
                "url": url
                + (
                    "/clash/providers/" + name + ".yaml"
                    if access_mode == "public"
                    else "/nodes.json"
                ),
                "path": "./proxy_providers/vrk.json",
                "interval": 3600,
                "health-check": {"enable": True, **HEALTH},
            }
        },
        "proxy-groups": groups([], "vrk"),
    }
    feed_nodes = copy.deepcopy(nodes)
    hops = []
    for n in feed_nodes:
        if n.get("dialer-proxy"):
            n["dialer-proxy"] = n["dialer-proxy"].replace("_carrier-", "_vrk-hop-", 1)
        if n["name"].startswith("_carrier-"):
            hops.append(
                {
                    "name": n["name"].replace("_carrier-", "_vrk-hop-", 1),
                    "type": "fallback",
                    "proxies": ["REJECT"],
                    "use": ["vrk"],
                    "filter": "^" + re.escape(n["name"]) + "$",
                    **HEALTH,
                }
            )
    example["proxy-groups"] += hops
    manifest = {
        "schema_version": 2,
        "name": name,
        "access_mode": access_mode,
        "selected_formats": formats,
        "rule_version": rule_version,
        "candidate_only": candidates,
        "routes": [
            {"id": r["id"], "country": r["exit_country"], "fingerprint": catalog.fingerprint(c, r)}
            for r in routes
        ],
        "rules": {k: {"sha256": digest(v)} for k, v in rules.items()},
        "formats": {
            "clash": {
                "profile": "desktop.json",
                "provider": "nodes.json",
                "core": "Mihomo >= 1.19.32",
            },
            "v2ray": {
                "file": "v2ray.txt",
                "encoding": "base64-utf8-uri-list",
                "nodes": len(shareable),
                "excluded_client_chains": [
                    n["name"] for n in nodes if n["name"] in names and n.get("dialer-proxy")
                ],
            },
        },
        "artifacts": {},
    }
    manifest["formats"] = {k: v for k, v in manifest["formats"].items() if k in formats}
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=".vrk-build-", dir=output.parent))
    try:
        for k, v in {
            "nodes.json": {"proxies": feed_nodes},
            "desktop.json": desktop,
            "openwrt-example.json": example,
        }.items():
            atomic(temp / k, v)
        if "v2ray" in formats:
            atomic(temp / "v2ray.txt", v2ray)
        for k, data in rules.items():
            atomic(temp / "rules" / (k + ".txt"), data)
        if "clash" in formats:
            # Use local fixed rule files while validating, never bootstrap over the subscription being built.
            check = read(temp / "desktop.json")
            for k, p in check["rule-providers"].items():
                p["type"] = "file"
                p["path"] = str(temp / "rules" / (k.removeprefix("domestic-") + ".txt"))
                p.pop("url")
                p.pop("interval")
                p.pop("proxy", None)
            atomic(temp / "validation.json", check)
            result = run(
                [mihomo, "-t", "-f", temp / "validation.json", "-d", temp],
                check=False,
                timeout=90,
            )
            if result.returncode:
                atomic(
                    output.with_name(output.name + ".validation.log"),
                    getattr(result, "stdout", "") + getattr(result, "stderr", ""),
                )
                raise Error(
                    "Mihomo rejects subscription; inspect private validation log; no release created"
                )
            (temp / "validation.json").unlink()
            shutil.rmtree(temp / "state", ignore_errors=True)
        if "clash" not in formats:
            for f in ("desktop.json", "nodes.json", "openwrt-example.json"):
                (temp / f).unlink()
            shutil.rmtree(temp / "rules", ignore_errors=True)
        files = [f for f in FILES if (temp / f).is_file()]
        for f in files:
            if f != "manifest.json":
                manifest["artifacts"][f] = digest((temp / f).read_bytes())
        manifest["revision"] = digest(encode(manifest))[:20]
        atomic(temp / "manifest.json", manifest)
        os.replace(temp, output)
    finally:
        if temp.exists():
            shutil.rmtree(temp)
    return {"revision": manifest["revision"], "routes": len(routes), "candidate_only": candidates}
