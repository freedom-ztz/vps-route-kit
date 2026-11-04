import json
from pathlib import Path
import statistics
import re
import subprocess
import tempfile
import time
from .util import Error, run, read


def cpu_snapshot(host=None, jump=None):
    if not host:
        return None
    for value in [host, jump]:
        if value and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", value):
            raise Error("invalid CPU sampling SSH host")
    args = ["ssh", "-T", "-oBatchMode=yes", "-oConnectTimeout=5"]
    if jump:
        args += ["-J", jump]
    script = """import glob,json,os,time
rows={}
for path in glob.glob('/proc/[0-9]*/stat'):
 try:
  text=open(path).read();comm=text[text.index('(')+1:text.rindex(')')]
  if comm not in ('xray','hysteria','realm'):continue
  fields=text[text.rindex(')')+2:].split();rows[path.split('/')[2]]={'comm':comm,'ticks':int(fields[11])+int(fields[12])}
 except (OSError,ValueError):pass
print(json.dumps({'time':time.monotonic(),'hz':os.sysconf('SC_CLK_TCK'),'processes':rows}))
"""
    result = run(args + [host, "python3 -"], input=script, check=False, timeout=15)
    if result.returncode:
        return {"error": "CPU SSH sampling failed"}
    return json.loads(result.stdout)


def cpu_usage(before, after):
    if not before or not after or "error" in before or "error" in after:
        return None
    elapsed = after["time"] - before["time"]
    if elapsed <= 0:
        return None
    return [
        {
            "pid": pid,
            "comm": p["comm"],
            "percent_one_core": round(
                (p["ticks"] - before["processes"][pid]["ticks"]) / after["hz"] / elapsed * 100, 3
            ),
        }
        for pid, p in after["processes"].items()
        if pid in before["processes"]
    ]


def benchmark(
    proxy,
    down,
    up,
    rounds=3,
    download_bytes=25_000_000,
    upload_bytes=8_000_000,
    cpu_host=None,
    jump=None,
    request_timeout=90,
):
    if rounds < 1 or rounds > 100:
        raise Error("rounds must be between 1 and 100")
    if request_timeout < 1:
        raise Error("timeout must be positive")
    if not down.startswith("https://") or not up.startswith("https://"):
        raise Error("benchmark requires explicit HTTPS endpoints")
    rows = []
    with tempfile.TemporaryDirectory(prefix="vrk-bench-") as directory:
        payload = Path(directory) / "upload"
        payload.write_bytes(b"\0" * upload_bytes)
        for round_no in range(1, rounds + 1):
            for direction, url in [("down", down), ("up", up)]:
                args = [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--noproxy",
                    "",
                    "--proxy",
                    proxy,
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    str(request_timeout),
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{json}",
                    url,
                ]
                if direction == "up":
                    args += ["--data-binary", "@" + str(payload)]
                before = cpu_snapshot(cpu_host, jump)
                r = run(args, check=False, timeout=request_timeout + 10)
                after = cpu_snapshot(cpu_host, jump)
                try:
                    meta = json.loads(r.stdout)
                except ValueError:
                    meta = {}
                byte_count = meta.get("size_download" if direction == "down" else "size_upload", 0)
                expected = download_bytes if direction == "down" else upload_bytes
                rows.append(
                    {
                        "round": round_no,
                        "direction": direction,
                        "exit": r.returncode,
                        "error": r.stderr[:1024],
                        "proxy_used": meta.get("proxy_used"),
                        "local_port": meta.get("local_port"),
                        "tls_seconds": meta.get("time_appconnect"),
                        "http_code": meta.get("http_code"),
                        "bytes": byte_count,
                        "expected_bytes": expected,
                        "completed": r.returncode == 0
                        and 200 <= meta.get("http_code", 0) < 300
                        and byte_count == expected,
                        "mbps": meta.get(
                            "speed_download" if direction == "down" else "speed_upload", 0
                        )
                        * 8
                        / 1e6,
                        "connect_seconds": meta.get("time_connect"),
                        "total_seconds": meta.get("time_total"),
                        "cpu": cpu_usage(before, after),
                        "cpu_sampling": {"before": before, "after": after},
                    }
                )
    return {
        "samples": rows,
        "median_completed_mbps": {
            direction: (
                statistics.median(v)
                if (
                    v := [r["mbps"] for r in rows if r["direction"] == direction and r["completed"]]
                )
                else None
            )
            for direction in ["down", "up"]
        },
    }
