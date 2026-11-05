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
from .verification import TIMINGS, probe, validate_cases


def clock_evidence(sent, received, elapsed, remote):
    """Bound remote-minus-local clock offset without assuming symmetric SSH latency."""
    first, last, probe_seconds = (
        remote["started"],
        remote["ended"],
        remote["probe_seconds"],
    )
    lower, upper = last - received, first - sent
    comparable = (
        0 <= probe_seconds <= elapsed + 0.5
        and abs(received - sent - elapsed) <= 0.5
        and abs(last - first - probe_seconds) <= 0.5
        and lower <= upper
    )
    return {
        "local_sent": sent,
        "local_received": received,
        "remote_started": first,
        "remote_ended": last,
        "comparable": comparable,
        "offset_seconds_min": lower if comparable else None,
        "offset_seconds_max": upper if comparable else None,
        "method": "remote-minus-local bounds; no symmetric-latency assumption",
    }


def segment(c, spec):
    if set(spec) != {"from", "to", "port", "transport"} or spec["to"] not in c["hosts"]:
        raise Error("invalid segment")
    catalog.port(spec["port"])
    if spec["transport"] not in ("tcp", "udp-echo"):
        raise Error("UDP segment checks require a controlled echo endpoint, not a UDP port scan")
    if spec["from"] != "local" and spec["from"] not in c["hosts"]:
        raise Error("unknown segment origin")
    code = """import socket,secrets,time,json
result={'started':time.time(),'ok':False}; started=time.monotonic(); s=None
try:
 s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if %r=='tcp' else socket.SOCK_DGRAM)
 s.settimeout(8); s.connect((%r,%r))
 if %r=='udp-echo':
  payload=secrets.token_bytes(1200); s.send(payload)
  if s.recv(1400)!=payload: raise ValueError('invalid echo')
 result['ok']=True
except (OSError,ValueError) as error: result['error_type']=type(error).__name__
finally:
 if s is not None: s.close()
result.update(ended=time.time(),probe_seconds=time.monotonic()-started)
print(json.dumps(result))
""" % (
        spec["transport"],
        c["hosts"][spec["to"]]["address"],
        spec["port"],
        spec["transport"],
    )
    sent = time.time()
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
        received, elapsed = time.time(), time.monotonic() - started
        if p.returncode:
            return {
                **spec,
                "status": "unmeasured",
                "reason": "probe_execution_failed; target path not established",
                "execution_exit": p.returncode,
                "elapsed": elapsed,
            }
        try:
            remote = json.loads(p.stdout)
            clock = clock_evidence(sent, received, elapsed, remote)
            if type(remote["ok"]) is not bool:
                raise ValueError("invalid probe status")
        except (ValueError, TypeError, KeyError):
            return {
                **spec,
                "status": "unmeasured",
                "reason": "invalid_probe_receipt",
                "elapsed": elapsed,
            }
        return {
            **spec,
            "status": "passed" if remote["ok"] else "failed",
            "elapsed": elapsed,
            "probe_seconds": remote["probe_seconds"],
            "error_type": remote.get("error_type"),
            "clock": clock,
        }
    except (Error, OSError) as error:
        return {
            **spec,
            "status": "unmeasured",
            "reason": "probe_execution_failed; target path not established",
            "error_type": type(error).__name__,
            "elapsed": time.monotonic() - started,
        }


def egress(proxy, url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise Error("egress endpoint must be explicit credential-free HTTPS")
    started = time.time()
    receipt = {"started": started, "ip": None, "ok": False, "meta": {}}
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
                "--write-out",
                "\n%{json}",
                url,
            ],
            check=False,
            timeout=20,
        )
        body, separator, raw_meta = p.stdout.rpartition("\n")
        try:
            meta = json.loads(raw_meta) if separator else {}
        except ValueError:
            meta = {}
        receipt.update(
            exit=p.returncode,
            error=p.stderr.replace(url, "<egress-url>")[:1024],
            meta={k: meta.get(k) for k in TIMINGS},
        )
        if p.returncode or not 200 <= meta.get("http_code", 0) < 300:
            receipt["failure"] = "curl_or_http"
            return receipt
        try:
            data = json.loads(body)
            value = data.get("ip", data.get("origin")) if isinstance(data, dict) else data
        except ValueError:
            value = body.strip()
        try:
            receipt.update(ip=str(ipaddress.IPv4Address(value)), ok=True)
        except (ValueError, TypeError):
            receipt["failure"] = "invalid_egress_ipv4"
        return receipt
    except (Error, OSError) as error:
        receipt.update(failure="probe_tool", error_type=type(error).__name__)
        return receipt
    finally:
        receipt["ended"] = time.time()


def diagnose(c, cases, output):
    catalog.validate(c)
    output = Path(output)
    if output.exists():
        raise Error("diagnosis output exists; preserve prior evidence")
    if set(cases) - {"routes", "evidence"} or not isinstance(cases["routes"], dict):
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
            egress_receipt = egress(spec["proxy"], spec["egress_url"])
            actual = egress_receipt["ip"]
            segments = [segment(c, s) for s in spec.get("segments", [])]
            from .exercise import exercise

            exercises = exercise(spec["proxy"], spec["exercise"]) if spec.get("exercise") else {}
            result["routes"][key] = {
                "fingerprint": catalog.fingerprint(c, routes[key]),
                "binding": (
                    catalog.binding(
                        c,
                        routes[key],
                        spec["targets"],
                        cases["evidence"]["batch_id"],
                        cases["evidence"]["core_versions"],
                    )
                    if cases.get("evidence")
                    else {}
                ),
                "checks": records,
                "exercises": exercises,
                "exit_ipv4": actual,
                "egress_probe": egress_receipt,
                "segments": segments,
                "ok": all(x["ok"] for x in records)
                and egress_receipt["ok"] is True
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
