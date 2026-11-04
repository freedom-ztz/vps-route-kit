"""Read-only, explicit segment probes and HTTPS egress evidence."""

import ipaddress
import json
import os
from pathlib import Path
import shlex
import time
import urllib.parse
from . import catalog
from .util import Error, atomic, run
from .verification import probe, validate_cases


def segment(c, spec):
    if set(spec) != {"from", "to", "port", "transport"} or spec["to"] not in c["hosts"]:
        raise Error("invalid segment")
    catalog.port(spec["port"])
    if spec["transport"] not in ("tcp", "udp-echo"):
        raise Error("UDP segment checks require a controlled echo endpoint, not a UDP port scan")
    if spec["from"] != "local" and spec["from"] not in c["hosts"]:
        raise Error("unknown segment origin")
    code = (
        "import socket,secrets; "
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if %r=='tcp' else socket.SOCK_DGRAM); "
        "s.settimeout(8); s.connect((%r,%r)); "
        % (spec["transport"], c["hosts"][spec["to"]]["address"], spec["port"])
    )
    if spec["transport"] == "udp-echo":
        code += "p=secrets.token_bytes(1200); s.send(p); assert s.recv(1400)==p; "
    code += "s.close(); print('ok')"
    started = time.monotonic()
    try:
        if spec["from"] == "local":
            import sys

            p = run([sys.executable, "-c", code], check=False, timeout=12)
        else:
            host = c["hosts"][spec["from"]]
            if not host.get("ssh"):
                return {**spec, "status": "unmeasured", "reason": "no SSH origin configured"}
            command = ["ssh", "-T", "-oBatchMode=yes", "-oConnectTimeout=8"]
            if host.get("jump"):
                command += ["-J", host["jump"]]
            command += [host["ssh"], shlex.join(["python3", "-c", code])]
            p = run(command, check=False, timeout=25)
        ok = p.returncode == 0 and p.stdout.strip() == "ok"
        return {
            **spec,
            "status": "passed" if ok else "failed",
            "elapsed": time.monotonic() - started,
        }
    except (Error, OSError):
        return {**spec, "status": "failed", "elapsed": time.monotonic() - started}


def egress(proxy, url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise Error("egress endpoint must be explicit credential-free HTTPS")
    try:
        p = run(
            [
                "curl",
                "-sS",
                "--noproxy",
                "",
                "--proxy",
                proxy,
                "--connect-timeout",
                "8",
                "--max-time",
                "15",
                "--max-filesize",
                "65536",
                "--fail",
                url,
            ],
            check=False,
            timeout=20,
        )
        if p.returncode:
            return None
        try:
            data = json.loads(p.stdout)
            value = data.get("ip", data.get("origin")) if isinstance(data, dict) else data
        except ValueError:
            value = p.stdout.strip()
        return str(ipaddress.IPv4Address(value))
    except (ValueError, Error, OSError, TypeError):
        return None


def diagnose(c, cases, output):
    catalog.validate(c)
    output = Path(output)
    if output.exists():
        raise Error("diagnosis output exists; preserve prior evidence")
    if set(cases) != {"routes"} or not isinstance(cases["routes"], dict):
        raise Error("diagnosis requires named route cases")
    routes = {r["id"]: r for r in c["routes"]}
    if set(cases["routes"]) - routes.keys():
        raise Error("diagnosis references unknown route")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    result = {
        "completed": False,
        "routes": {},
        "attribution": "undetermined; correlate segment evidence and core logs",
    }
    try:
        for key, spec in cases["routes"].items():
            if set(spec) - {"proxy", "targets", "egress_url", "segments", "exercise"}:
                raise Error("unknown diagnosis field")
            validate_cases({"proxies": {key: spec["proxy"]}, "targets": spec["targets"]})
            records = [probe(key, spec["proxy"], target, 8, 15) for target in spec["targets"]]
            actual = egress(spec["proxy"], spec["egress_url"])
            segments = [segment(c, s) for s in spec.get("segments", [])]
            from .exercise import exercise

            exercises = exercise(spec["proxy"], spec["exercise"]) if spec.get("exercise") else {}
            result["routes"][key] = {
                "fingerprint": catalog.fingerprint(c, routes[key]),
                "checks": records,
                "exercises": exercises,
                "exit_ipv4": actual,
                "segments": segments,
                "ok": all(x["ok"] for x in records)
                and actual == routes[key]["expected_exit_ipv4"]
                and all(x["status"] == "passed" for x in segments)
                and all(x["ok"] for x in exercises.values()),
            }
        result["completed"] = True
    finally:
        atomic(output, result)
    return {
        "completed": result["completed"],
        "routes": {
            k: {"ok": v["ok"], "segments": len(v["segments"])} for k, v in result["routes"].items()
        },
        "all_passed": result["completed"]
        and bool(result["routes"])
        and all(v["ok"] for v in result["routes"].values()),
    }
