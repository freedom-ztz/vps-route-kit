"""Read-only network checks with immutable first-attempt evidence."""

import concurrent.futures
import json
import math
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
from .util import Error, atomic, run

TIMINGS = (
    "http_code",
    "local_port",
    "remote_ip",
    "proxy_used",
    "ssl_verify_result",
    "time_connect",
    "time_appconnect",
    "time_starttransfer",
    "time_total",
)


def validate_cases(c):
    if not isinstance(c, dict) or set(c) - {
        "proxies",
        "targets",
        "rounds",
        "interval",
        "workers",
        "connect_timeout",
        "timeout",
        "excluded",
    }:
        raise Error("invalid verification manifest")
    if not isinstance(c.get("proxies"), dict) or not c["proxies"]:
        raise Error("verification requires named proxy URLs")
    for name, url in c["proxies"].items():
        if not isinstance(name, str) or "/" in name or not isinstance(url, str):
            raise Error("invalid proxy name or URL")
        u = urllib.parse.urlsplit(url)
        if (
            not name
            or u.scheme not in ("socks5h", "http", "https")
            or not u.hostname
            or not u.port
            or u.username
            or u.password
        ):
            raise Error("invalid proxy URL; use a dedicated listener without URL credentials")
    if not isinstance(c.get("targets"), list) or not c["targets"]:
        raise Error("verification requires explicit HTTPS targets")
    names = set()
    for t in c["targets"]:
        if not isinstance(t, dict) or set(t) != {"name", "url", "expect"}:
            raise Error("target requires name/url/expect")
        if not isinstance(t["name"], str) or "/" in t["name"] or not isinstance(t["url"], str):
            raise Error("invalid target name or URL")
        u = urllib.parse.urlsplit(t["url"])
        if (
            not t["name"]
            or t["name"] in names
            or u.scheme != "https"
            or not u.hostname
            or u.username
            or u.password
            or type(t["expect"]) is not int
            or not 100 <= t["expect"] <= 599
        ):
            raise Error("invalid HTTPS verification target")
        names.add(t["name"])
    for k, default in [("rounds", 60), ("workers", 4)]:
        value = c.get(k, default)
        if type(value) is not int or value < 1 or value > (32 if k == "workers" else 10000):
            raise Error("invalid verification " + k)
    for k, default in [("interval", 30), ("connect_timeout", 8), ("timeout", 12)]:
        v = c.get(k, default)
        if (
            type(v) not in (int, float)
            or not math.isfinite(v)
            or v < (0 if k == "interval" else 0.1)
        ):
            raise Error("invalid verification " + k)
    excluded = c.get("excluded", {})
    if not isinstance(excluded, dict) or any(
        n not in c["proxies"] or not isinstance(reason, str) or not reason
        for n, reason in excluded.items()
    ):
        raise Error("exclusions must name a declared proxy and explain why")
    if len(excluded) == len(c["proxies"]):
        raise Error("no active verification cases")
    return c


def probe(name, proxy, target, connect_timeout, timeout):
    started = time.time()
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--noproxy",
        "",
        "--proxy",
        proxy,
        "--connect-timeout",
        str(connect_timeout),
        "--max-time",
        str(timeout),
        "--output",
        os.devnull,
        "--write-out",
        "%{json}",
        target["url"],
    ]
    try:
        p = run(command, check=False, timeout=timeout + 5)
    except (Error, OSError) as e:
        return {
            "proxy": name,
            "target": target["name"],
            "started": started,
            "ok": False,
            "failure": "local_runner",
            "error": str(e),
            "metrics": {},
        }
    try:
        meta = json.loads(p.stdout)
        if not isinstance(meta, dict):
            raise ValueError()
    except ValueError:
        meta = {}
    ok = p.returncode == 0 and meta.get("http_code") == target["expect"]
    failure = (
        None
        if ok
        else "proxy_or_transport" if p.returncode else "http_status" if meta else "invalid_metrics"
    )
    return {
        "proxy": name,
        "target": target["name"],
        "started": started,
        "exit": p.returncode,
        "expected_status": target["expect"],
        "ok": ok,
        "failure": failure,
        "error": p.stderr[:1024],
        "metrics": {k: meta.get(k) for k in TIMINGS},
    }


def verify(c, output):
    c = validate_cases(c)
    output = Path(output)
    summary_path = output.with_name(output.name + ".summary.json")
    if output.exists() or summary_path.exists():
        raise Error("verification output exists; preserve prior evidence and choose a new path")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    start = time.monotonic()
    counts = {}
    rounds_done = 0
    completed = False
    summary = {"completed": False, "excluded": c.get("excluded", {}), "cases": counts}
    try:
        with (
            os.fdopen(fd, "w") as f,
            concurrent.futures.ThreadPoolExecutor(max_workers=c.get("workers", 4)) as pool,
        ):
            for round_no in range(1, c.get("rounds", 60) + 1):
                futures = [
                    pool.submit(probe, n, url, t, c.get("connect_timeout", 8), c.get("timeout", 12))
                    for n, url in c["proxies"].items()
                    if n not in c.get("excluded", {})
                    for t in c["targets"]
                ]
                for future in concurrent.futures.as_completed(futures):
                    record = future.result()
                    record["round"] = round_no
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    f.flush()
                    key = record["proxy"] + "/" + record["target"]
                    case = counts.setdefault(key, {"checks": 0, "failures": 0})
                    case["checks"] += 1
                    case["failures"] += int(not record["ok"])
                os.fsync(f.fileno())
                rounds_done = round_no
                if round_no % 5 == 0:
                    print(
                        f"round {round_no}: {sum(v['failures'] for v in counts.values())} failures",
                        flush=True,
                    )
                delay = start + round_no * c.get("interval", 30) - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            completed = True
    finally:
        summary.update(
            completed=completed,
            rounds=rounds_done,
            elapsed_seconds=time.monotonic() - start,
            checks=sum(v["checks"] for v in counts.values()),
            failures=sum(v["failures"] for v in counts.values()),
        )
        summary["active_cases_passed"] = completed and summary["failures"] == 0
        summary["all_declared_passed"] = summary["active_cases_passed"] and not summary["excluded"]
        atomic(summary_path, summary)
    return summary
