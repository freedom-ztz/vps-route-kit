import json
from .config import referenced_nodes
from .util import encode


def node_outbound(n, secret, tag):
    stream = {
        "network": "xhttp" if n["protocol"] == "xhttp" else "raw",
        "security": "reality",
        "realitySettings": {
            "serverName": n["server_name"],
            "fingerprint": "chrome",
            "publicKey": n["public_key"],
            "shortId": n["short_id"],
        },
    }
    user = {"id": secret["uuid"], "encryption": "none"}
    if n["protocol"] == "vision":
        user["flow"] = "xtls-rprx-vision"
    else:
        stream["xhttpSettings"] = {"path": n["path"], "mode": "stream-one"}
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": n["address"], "port": n["port"], "users": [user]}]},
        "streamSettings": stream,
    }


def bridge_required(c):
    return any(l["protocol"] == "hysteria2" for l in c["listeners"]) and (
        bool(c["routing"].get("rules")) or c["routing"]["default"] != "local"
    )


def render(c, s, root="/var/lib/vrk"):
    files = {}
    for component, servers in c.get("service_dns", {}).items():
        files[f"resolv-{component}.conf"] = "".join(f"nameserver {server}\n" for server in servers)
    services = {}
    bindings = []
    referenced = sorted(referenced_nodes(c))
    inbounds = []
    outbounds = [
        {"tag": "local", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
        {"tag": "reject", "protocol": "blackhole"},
    ]
    for i, key in enumerate(referenced):
        n = c["nodes"][key]
        sec = s[n["secret"]]
        if n["protocol"] == "hysteria2":
            client = {
                "server": f"{n['address']}:{n['port']}",
                "auth": sec["password"],
                "tls": {"sni": n["server_name"], "insecure": False},
                "socks5": {"listen": f"127.0.0.1:{18100+i}"},
            }
            files[f"hy-client-{key}.json"] = encode(client)
            services[f"vrk-hy-client-{key}"] = (
                "hysteria",
                ["client", "-c", f"{root}/current/hy-client-{key}.json"],
            )
            outbounds.append(
                {
                    "tag": "node:" + key,
                    "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.1", "port": 18100 + i}]},
                }
            )
        else:
            outbounds.append(node_outbound(n, sec, "node:" + key))
    if bridge_required(c):
        inbounds.append(
            {
                "tag": "hy-bridge",
                "listen": "127.0.0.1",
                "port": 18080,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        )
    for l in c["listeners"]:
        secret = s[l["secret"]]
        if l["protocol"] == "hysteria2":
            d = {
                "listen": f"{l.get('listen','0.0.0.0')}:{l['port']}",
                "auth": {"type": "password", "password": secret["password"]},
                "congestion": {"type": "bbr", "bbrProfile": "standard"},
                "resolver": {"type": "system"},
                "masquerade": {"type": "file", "file": {"dir": f"{root}/current/www"}},
            }
            cert = l["certificate"]
            if cert["mode"] == "acme":
                d["acme"] = {
                    "domains": [l["server_name"]],
                    "email": cert["email"],
                    "ca": "letsencrypt",
                    "dir": f'{root}/acme/{l["id"]}',
                    "type": "http",
                    "listenHost": "0.0.0.0",
                    "http": {"altPort": 80},
                }
            else:
                d["tls"] = {"cert": cert["cert"], "key": cert["key"]}
            if bridge_required(c):
                d["outbounds"] = [
                    {"name": "router", "type": "socks5", "socks5": {"addr": "127.0.0.1:18080"}}
                ]
            else:
                d["outbounds"] = [{"name": "local", "type": "direct", "direct": {"mode": "4"}}]
            files[f'hy-{l["id"]}.json'] = encode(d)
            services[f'vrk-hy-{l["id"]}'] = (
                "hysteria",
                ["server", "-c", f'{root}/current/hy-{l["id"]}.json'],
            )
            continue
        user = {"id": secret["uuid"]}
        if l["protocol"] == "vision":
            user["flow"] = "xtls-rprx-vision"
        stream = {
            "network": "raw" if l["protocol"] == "vision" else "xhttp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": f"{l['target']}:{l.get('target_port',443)}",
                "serverNames": [l["server_name"]],
                "privateKey": secret["private_key"],
                "shortIds": [secret["short_id"]],
            },
        }
        if l["protocol"] == "xhttp":
            stream["xhttpSettings"] = {"path": l["path"], "mode": "stream-one"}
        inbounds.append(
            {
                "tag": l["id"],
                "listen": l.get("listen", "0.0.0.0"),
                "port": l["port"],
                "protocol": "vless",
                "settings": {"clients": [user], "decryption": "none"},
                "streamSettings": stream,
            }
        )
    if inbounds:
        rules = []
        for r in c["routing"].get("rules", []):
            rule = {"type": "field", "outboundTag": r["action"]}
            if "cidr" in r:
                rule["ip"] = r["cidr"]
            else:
                rule["domain"] = ["full:" + v for v in r.get("domain", [])] + [
                    "domain:" + v for v in r.get("suffix", [])
                ]
            rules.append(rule)
        rules.append(
            {"type": "field", "network": "tcp,udp", "outboundTag": c["routing"]["default"]}
        )
        files["xray.json"] = encode(
            {
                "log": {"loglevel": "warning"},
                "inbounds": inbounds,
                "outbounds": outbounds,
                "routing": {"domainStrategy": "AsIs", "rules": rules},
            }
        )
        services["vrk-xray"] = ("xray", ["run", "-config", f"{root}/current/xray.json"])
    if c.get("relays"):
        lines = ["[log]", 'level = "warn"', "[network]", "no_tcp = false", "use_udp = false"]
        for r in c["relays"]:
            t = r.get("transports", ["tcp"])
            lines += [
                "[[endpoints]]",
                "listen = " + json.dumps(f"{r.get('listen','0.0.0.0')}:{r['port']}"),
                "remote = " + json.dumps(f"{r['remote']}:{r['remote_port']}"),
                "[endpoints.network]",
                "no_tcp = " + str("tcp" not in t).lower(),
                "use_udp = " + str("udp" in t).lower(),
            ]
        files["realm.toml"] = "\n".join(lines) + "\n"
        services["vrk-realm"] = ("realm", ["-c", f"{root}/current/realm.toml"])
    files["www/index.html"] = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Network Status</title><h1>Network Status</h1><p>Service available.</p></html>\n'
    )
    return files, services


def client_nodes(c, s):
    result = []
    for l in c["listeners"]:
        sec = s[l["secret"]]
        n = {
            "name": l["id"],
            "protocol": l["protocol"],
            "address": c["address"],
            "port": l["port"],
            "server_name": l["server_name"],
            "secret": l["secret"],
        }
        if l["protocol"] != "hysteria2":
            n.update(public_key=sec["public_key"], short_id=sec["short_id"])
        if l["protocol"] == "xhttp":
            n["path"] = l["path"]
        result.append(n)
    return result
