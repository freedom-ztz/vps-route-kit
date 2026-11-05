"""Opt-in controlled long-stream, idle TLS, transfer and SOCKS UDP probes."""

import concurrent.futures
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import time
import urllib.parse
from .util import Error, run


def endpoint(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise Error("exercise requires credential-free controlled HTTPS URLs")
    return u


def exact(s, n):
    data = b""
    while len(data) < n:
        block = s.recv(n - len(data))
        if not block:
            raise Error("SOCKS connection closed")
        data += block
    return data


def destination(host, port):
    try:
        return (
            b"\x01" + socket.inet_aton(str(ipaddress.IPv4Address(host))) + struct.pack("!H", port)
        )
    except ValueError:
        host = host.encode("idna")
        if len(host) > 253:
            raise Error("invalid SOCKS destination")
        return b"\x03" + bytes([len(host)]) + host + struct.pack("!H", port)


def reply(s):
    header = exact(s, 4)
    if header[:2] != b"\x05\x00":
        raise Error("SOCKS request rejected")
    if header[3] == 1:
        host = socket.inet_ntoa(exact(s, 4))
    elif header[3] == 3:
        host = exact(s, exact(s, 1)[0]).decode()
    else:
        raise Error("unsupported SOCKS reply")
    return host, struct.unpack("!H", exact(s, 2))[0]


def socks(proxy, host, port, udp=False):
    u = urllib.parse.urlsplit(proxy)
    if u.scheme != "socks5h" or not u.hostname or not u.port or u.username:
        raise Error("idle/UDP exercise requires an explicit socks5h listener")
    s = socket.create_connection((u.hostname, u.port), timeout=15)
    try:
        s.sendall(b"\x05\x01\x00")
        if exact(s, 2) != b"\x05\x00":
            raise Error("SOCKS authentication unsupported")
        s.sendall(b"\x05" + (b"\x03" if udp else b"\x01") + b"\x00" + destination(host, port))
        relay = reply(s)
        return s, relay
    except BaseException:
        s.close()
        raise


def idle(proxy, url, seconds):
    u = endpoint(url)
    if type(seconds) not in (int, float) or not 1 <= seconds <= 300:
        raise Error("idle seconds must be 1..300")
    s, _ = socks(proxy, u.hostname, u.port or 443)
    conn = http.client.HTTPConnection(u.hostname, timeout=15)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        original = conn.sock
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        conn.request("GET", path)
        response = conn.getresponse()
        response.read(65536)
        if response.status != 204 or conn.sock is not original:
            raise Error("controlled idle endpoint must return 204 with HTTP keep-alive")
        local = original.getsockname()[1]
        time.sleep(seconds)
        conn.request("GET", path)
        response = conn.getresponse()
        response.read(65536)
        return {
            "ok": response.status == 204 and conn.sock is original,
            "same_connection": conn.sock is original,
            "local_port": local,
            "idle_seconds": seconds,
        }
    finally:
        conn.close()
        s.close()


def udp(proxy, host, port, size=1200):
    if type(size) is not int or not 1 <= size <= 1400:
        raise Error("UDP echo size must be 1..1400")
    if type(port) is not int or not 1 <= port <= 65535:
        raise Error("invalid UDP echo port")
    control, relay = socks(proxy, "0.0.0.0", 0, True)
    try:
        relay_host = relay[0] if relay[0] != "0.0.0.0" else urllib.parse.urlsplit(proxy).hostname
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(15)
            payload = secrets.token_bytes(size)
            s.sendto(b"\x00\x00\x00" + destination(host, port) + payload, (relay_host, relay[1]))
            data, _ = s.recvfrom(4096)
            if data[:3] != b"\x00\x00\x00":
                raise Error("invalid UDP SOCKS frame")
            offset = (
                10 if data[3] == 1 else 7 + data[4] if data[3] == 3 else 22 if data[3] == 4 else -1
            )
            return {"ok": offset > 0 and data[offset:] == payload, "payload_bytes": size}
    finally:
        control.close()


def transfer(proxy, url, upload=False):
    endpoint(url)
    args = [
        "curl",
        "-sS",
        "--noproxy",
        "",
        "--proxy",
        proxy,
        "--connect-timeout",
        "8",
        "--max-time",
        "90",
        "-o",
        "/dev/null",
        "-w",
        "%{json}",
    ]
    kwargs = {}
    if upload:
        args += ["--data-binary", "@-"]
        kwargs["input"] = "0" * 8_000_000
    p = run(args + [url], check=False, timeout=95, **kwargs)
    try:
        m = json.loads(p.stdout)
    except ValueError:
        m = {}
    expected = 8_000_000 if upload else 25_000_000
    size = m.get("size_upload" if upload else "size_download", 0)
    return {
        "ok": p.returncode == 0 and 200 <= m.get("http_code", 0) < 300 and size == expected,
        "exit": p.returncode,
        "bytes": size,
        "seconds": m.get("time_total"),
    }


def exercise(proxy, c):
    if set(c) - {
        "stream_url",
        "stream_seconds",
        "idle_url",
        "idle_seconds",
        "download_url",
        "upload_url",
        "udp",
    }:
        raise Error("invalid exercise configuration")
    results = {}

    def attempt(key, fn):
        try:
            results[key] = fn()
        except (Error, OSError, ValueError, http.client.HTTPException) as error:
            results[key] = {
                "ok": False,
                "reason": "controlled_probe_failed; inspect core logs",
                "error_type": type(error).__name__,
                "phase": key,
            }

    if c.get("stream_url"):

        def stream():
            endpoint(c["stream_url"])
            duration = c.get("stream_seconds", 30)
            if type(duration) not in (int, float) or not 1 <= duration <= 300:
                raise Error("invalid stream duration")
            p = run(
                [
                    "curl",
                    "-sS",
                    "--noproxy",
                    "",
                    "--proxy",
                    proxy,
                    "--max-time",
                    str(duration + 25),
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{json}",
                    c["stream_url"],
                ],
                check=False,
                timeout=duration + 30,
            )
            m = json.loads(p.stdout)
            return {
                "ok": p.returncode == 0
                and m.get("http_code") == 200
                and m.get("size_download", 0) > 0
                and m.get("time_total", 0) - m.get("time_starttransfer", 0) >= duration - 1,
                "exit": p.returncode,
                "seconds": m.get("time_total"),
                "bytes": m.get("size_download"),
            }

        attempt("stream", stream)
    if c.get("idle_url"):
        attempt("idle", lambda: idle(proxy, c["idle_url"], c.get("idle_seconds", 30)))
    if c.get("download_url") and c.get("upload_url"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(attempt, "download", lambda: transfer(proxy, c["download_url"]))
            b = pool.submit(attempt, "upload", lambda: transfer(proxy, c["upload_url"], True))
            a.result()
            b.result()
    if c.get("udp"):
        spec = c["udp"]
        attempt("udp", lambda: udp(proxy, spec["host"], spec["port"], spec.get("size", 1200)))
        results["udp"]["target"] = {"host": spec["host"], "port": spec["port"]}
    if not results:
        raise Error("exercise needs explicit controlled endpoints")
    return results
