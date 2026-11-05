"""Explicit native Mihomo smoke: simulated country fallback and provider failure cache."""

import argparse
import http.server
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--mihomo", required=True)
parser.add_argument("--output")
a = parser.parse_args()


def readn(s, n):
    data = b""
    while len(data) < n:
        b = s.recv(n - len(data))
        if not b:
            raise EOFError()
        data += b
    return data


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(5)
        try:
            h = readn(s, 2)
            readn(s, h[1])
            s.sendall(b"\x05\x00")
            h = readn(s, 4)
            readn(s, 4 if h[3] == 1 else readn(s, 1)[0] if h[3] == 3 else 16)
            readn(s, 2)
            s.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            data = s.recv(4096)
            if b"/generate_204" in data:
                s.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            else:
                body = self.server.label.encode()
                s.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
        except (OSError, EOFError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


servers = []
for label in ("SG-A", "SG-B", "JP", "US"):
    s = Server(("127.0.0.1", 0), Socks)
    s.label = label
    threading.Thread(target=s.serve_forever, daemon=True).start()
    servers.append(s)
nodes = [
    {"name": s.label, "type": "socks5", "server": "127.0.0.1", "port": s.server_address[1]}
    for s in servers
]
mode = {"status": 200, "body": json.dumps({"proxies": nodes}).encode()}


class Feed(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if mode["status"] == "timeout":
            time.sleep(7)
            return
        self.send_response(mode["status"])
        self.end_headers()
        try:
            self.wfile.write(mode["body"])
        except OSError:
            pass

    def log_message(self, *args):
        pass


feed = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Feed)
threading.Thread(target=feed.serve_forever, daemon=True).start()


def freeport():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


apiport, proxyport = freeport(), freeport()


def api(path, method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{apiport}" + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def names():
    return [n["name"] for n in json.loads(api("/providers/proxies/vrk")[1]).get("proxies", [])]


def request():
    p = subprocess.run(
        [
            "curl",
            "-sS",
            "--noproxy",
            "",
            "--proxy",
            f"socks5h://127.0.0.1:{proxyport}",
            "--max-time",
            "3",
            "http://target.invalid/probe",
        ],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout.strip()


def await_country(allowed, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, body = request()
        if code == 0 and body in allowed:
            return body
        time.sleep(0.5)
    raise AssertionError("simulated fallback failed: " + repr((code, body)))


result = {"simulation": True, "production_network_test": False}
p = None
try:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        state = root / "state"
        state.mkdir()
        config = {
            "mode": "rule",
            "log-level": "warning",
            "mixed-port": proxyport,
            "external-controller": f"127.0.0.1:{apiport}",
            "proxy-providers": {
                "vrk": {
                    "type": "http",
                    "proxy": "DIRECT",
                    "url": f"http://127.0.0.1:{feed.server_port}/feed",
                    "path": "./nodes.json",
                    "interval": 3600,
                    "health-check": {
                        "enable": True,
                        "url": "http://health.invalid/generate_204",
                        "interval": 1,
                        "timeout": 800,
                        "lazy": False,
                        "expected-status": 204,
                    },
                }
            },
            "proxy-groups": [
                {
                    "name": "auto",
                    "type": "fallback",
                    "proxies": ["REJECT"],
                    "use": ["vrk"],
                    "url": "http://health.invalid/generate_204",
                    "interval": 1,
                    "timeout": 800,
                    "lazy": False,
                    "expected-status": 204,
                }
            ],
            "rules": ["MATCH,auto"],
        }
        cfg = root / "config.json"
        cfg.write_text(json.dumps(config))
        log = (root / "core.log").open("w")

        def start(directory):
            proc = subprocess.Popen(
                [a.mihomo, "-f", str(cfg), "-d", str(directory)], stdout=log, stderr=log
            )
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    if ("proxy-providers" not in config and api("/proxies")[0] == 200) or names():
                        return proc
                except (OSError, ValueError, KeyError):
                    pass
                time.sleep(0.2)
            return proc

        p = start(state)
        result["initial"] = await_country({"SG-A", "SG-B"})
        for label, status, body in [
            ("404", 404, b""),
            ("invalid", 200, b"not yaml"),
            ("empty", 200, b'{"proxies":[]}'),
            ("timeout", "timeout", b""),
        ]:
            mode.update(status=status, body=body)
            code, _ = api("/providers/proxies/vrk", "PUT")
            assert code >= 400 and len(names()) == 4
            assert await_country({"SG-A", "SG-B"})
            result[label] = {"cache_preserved": True, "update_status": code}
        mode.update(status=404, body=b"")
        p.terminate()
        p.wait()
        p = start(state)
        result["cached_restart"] = await_country({"SG-A", "SG-B"})
        mode.update(status=200, body=json.dumps({"proxies": nodes}).encode())
        for s in servers[:2]:
            s.shutdown()
            s.server_close()
        result["all_sg_failed"] = await_country({"JP"})
        servers[2].shutdown()
        servers[2].server_close()
        result["jp_failed"] = await_country({"US"})
        servers[3].shutdown()
        servers[3].server_close()
        time.sleep(2)
        code, body = request()
        assert code != 0
        assert json.loads(api("/proxies/auto")[1])["now"] == "REJECT"
        result["all_failed_rejected"] = True
        mode.update(body=json.dumps({"proxies": [nodes[-1]]}).encode())
        assert api("/providers/proxies/vrk", "PUT")[0] == 204
        assert names() == ["US"]
        result["node_removal"] = True
        p.terminate()
        p.wait()
        p = None
        mode.update(status=404, body=b"")
        empty = root / "empty"
        empty.mkdir()
        p = start(empty)
        code, body = request()
        assert code != 0 and not names()
        assert json.loads(api("/proxies/auto")[1])["now"] == "REJECT"
        result["empty_first_start_rejected"] = True
        p.terminate()
        p.wait()
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from vrk.subscription import groups

        config.pop("proxy-providers")
        config["proxies"] = nodes
        config["proxy-groups"] = groups([n["name"] for n in nodes])
        config["proxy-groups"][1].update(
            url="http://health.invalid/generate_204", interval=1, timeout=800
        )
        config["rules"] = ["MATCH,外网"]
        cfg.write_text(json.dumps(config))
        inline = root / "inline"
        inline.mkdir()
        p = start(inline)
        time.sleep(2)
        assert request()[0] != 0
        group = json.loads(api("/proxies/" + urllib.parse.quote("自动"))[1])
        assert group["now"] == "REJECT"
        result["inline_all_failed_rejected"] = True
finally:
    if p and p.poll() is None:
        p.terminate()
        p.wait()
    for s in servers:
        s.shutdown()
        s.server_close()
    feed.shutdown()
if a.output:
    Path(a.output).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
