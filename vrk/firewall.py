"""Scoped nft rules only; never flush or replace another firewall."""

import json
from .util import Error, run


def check():
    p = run(["nft", "-j", "list", "ruleset"])
    rules = json.loads(p.stdout).get("nftables", [])
    for item in rules:
        c = item.get("chain", {})
        if c.get("hook") == "input" and c.get("policy") == "drop" and c.get("table") != "vrk":
            raise Error(
                "existing INPUT drop policy: integrate required ports into that firewall explicitly"
            )
        r = item.get("rule", {})
        if r.get("table") == "vrk":
            continue
        # Terminal drop/reject rules cannot be safely overridden by another base chain.
        if any("drop" in e or "reject" in e for e in r.get("expr", [])):
            raise Error("existing terminal firewall rule: refuse automatic firewall coordination")
    return True


def rules(c):
    ports = {"tcp": set(), "udp": set()}
    for t, h, p in c["_bindings"]:
        if h not in ("127.0.0.1", "::1"):
            ports[t].add(p)
    if any(l.get("certificate", {}).get("mode") == "acme" for l in c["listeners"]):
        ports["tcp"].add(80)
    lines = [
        "table inet vrk {",
        " chain input {",
        "  type filter hook input priority -10; policy accept;",
    ]
    for t, values in ports.items():
        if values:
            lines.append("  " + t + " dport { " + ", ".join(map(str, sorted(values))) + " } accept")
    return "\n".join(lines + [" }", "}"]) + "\n"


def service(root):
    return f"""# Managed by VPS Route Kit
[Unit]
Description=VPS Route Kit scoped firewall
Before=vrk-xray.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f {root}/current/firewall.nft
ExecStop=/usr/sbin/nft delete table inet vrk
[Install]
WantedBy=multi-user.target
"""
