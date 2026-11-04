import urllib.parse
from .render import client_nodes, node_outbound
from .util import Error
from .config import address as check_address, port as check_port


def export(c, s, kind, address=None, ports=None, listener=None, name_prefix="", dialer_proxy=None):
    if (
        not isinstance(name_prefix, str)
        or len(name_prefix) > 80
        or any(ord(x) < 32 for x in name_prefix)
    ):
        raise Error("invalid name prefix")
    if dialer_proxy is not None:
        if (
            kind != "mihomo"
            or not isinstance(dialer_proxy, str)
            or not dialer_proxy
            or len(dialer_proxy) > 128
            or not dialer_proxy.isprintable()
        ):
            raise Error("dialer-proxy requires a printable Mihomo proxy/group name")
    if address:
        check_address(address)
    if ports is not None:
        if not isinstance(ports, dict):
            raise Error("port-map must be an object")
        ids = {l["id"] for l in c["listeners"]}
        for key, value in ports.items():
            if key not in ids:
                raise Error("unknown listener in port-map: " + str(key))
            check_port(value)
    nodes = client_nodes(c, s)
    if listener:
        nodes = [n for n in nodes if n["name"] == listener]
    if not nodes:
        raise Error("no matching listener")
    for n in nodes:
        if address:
            n["address"] = address
        if ports and n["name"] in ports:
            n["port"] = int(ports[n["name"]])
        n["name"] = name_prefix + n["name"]
    if kind == "nodes":
        from .config import name as check_name

        result = {"nodes": {}, "secrets": {}}
        for n in nodes:
            check_name(n["name"])
            sid = name_prefix + n["secret"]
            check_name(sid)
            result["nodes"][n["name"]] = {
                **{k: v for k, v in n.items() if k != "name"},
                "secret": sid,
            }
            result["secrets"][sid] = {
                k: v for k, v in s[n["secret"]].items() if k in ("uuid", "password")
            }
        return result
    if kind == "mihomo":
        result = []
        for n in nodes:
            sec = s[n["secret"]]
            p = {"name": n["name"], "server": n["address"], "port": n["port"], "udp": True}
            if n["protocol"] == "hysteria2":
                p.update(
                    type="hysteria2",
                    password=sec["password"],
                    sni=n["server_name"],
                    **{"skip-cert-verify": False},
                )
            else:
                p.update(
                    type="vless",
                    uuid=sec["uuid"],
                    tls=True,
                    servername=n["server_name"],
                    **{
                        "client-fingerprint": "chrome",
                        "reality-opts": {"public-key": n["public_key"], "short-id": n["short_id"]},
                    },
                )
                if n["protocol"] == "vision":
                    p["flow"] = "xtls-rprx-vision"
                    p["network"] = "tcp"
                else:
                    p.update(
                        network="xhttp",
                        alpn=["h2"],
                        **{"xhttp-opts": {"path": n["path"], "mode": "stream-one"}},
                    )
            if dialer_proxy is not None:
                if dialer_proxy == p["name"]:
                    raise Error("dialer-proxy cannot refer to itself")
                p["dialer-proxy"] = dialer_proxy
            result.append(p)
        return {"proxies": result}
    if kind == "xray":
        if any(n["protocol"] == "hysteria2" for n in nodes):
            raise Error(
                "Xray export requires --listener vision/xhttp; use official Hysteria client for hysteria2"
            )
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [node_outbound(n, s[n["secret"]], n["name"]) for n in nodes],
        }
    if kind == "hysteria":
        if len(nodes) != 1 or nodes[0]["protocol"] != "hysteria2":
            raise Error("select one Hysteria listener")
        n = nodes[0]
        return {
            "server": f"{n['address']}:{n['port']}",
            "auth": s[n["secret"]]["password"],
            "tls": {"sni": n["server_name"], "insecure": False},
            "socks5": {"listen": "127.0.0.1:10808"},
        }
    if kind == "uri":
        output = []
        for n in nodes:
            sec = s[n["secret"]]
            host = n["address"] if ":" not in n["address"] else "[" + n["address"] + "]"
            if n["protocol"] == "hysteria2":
                u = (
                    "hysteria2://"
                    + urllib.parse.quote(sec["password"], safe="")
                    + "@"
                    + host
                    + ":"
                    + str(n["port"])
                    + "/?"
                    + urllib.parse.urlencode({"sni": n["server_name"], "insecure": "0"})
                )
            else:
                q = {
                    "encryption": "none",
                    "security": "reality",
                    "sni": n["server_name"],
                    "fp": "chrome",
                    "pbk": n["public_key"],
                    "sid": n["short_id"],
                    "type": "tcp" if n["protocol"] == "vision" else "xhttp",
                }
                if n["protocol"] == "vision":
                    q["flow"] = "xtls-rprx-vision"
                else:
                    q.update(path=n["path"], mode="stream-one", alpn="h2")
                u = (
                    "vless://"
                    + sec["uuid"]
                    + "@"
                    + host
                    + ":"
                    + str(n["port"])
                    + "?"
                    + urllib.parse.urlencode(q)
                )
            output.append(u + "#" + urllib.parse.quote(n["name"]))
        return "\n".join(output) + "\n"
    raise Error("unknown export format")
