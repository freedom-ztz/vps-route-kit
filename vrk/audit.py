"""Read-only staged route audit; no deployments, policy changes, or implicit retries."""

import copy
import fcntl
import hashlib
from pathlib import Path
import socket
import time

from . import catalog
from .diagnostics import benchmark
from .route_diagnostics import diagnose
from .util import Error, atomic, encode, read
from .verification import probe, validate_cases, verify


def tcp_entry(node):
    if node["type"] == "hysteria2":
        return {"status": "not_applicable", "reason": "QUIC requires a real handshake"}
    started = time.monotonic()
    try:
        with socket.create_connection((node["server"], node["port"]), timeout=5):
            return {"status": "passed", "seconds": time.monotonic() - started}
    except OSError as error:
        return {
            "status": "failed",
            "seconds": time.monotonic() - started,
            "error_type": type(error).__name__,
        }


def attribution(entry, normal, pinned, configuration):
    if configuration.get("matches") is False:
        return "configuration_mismatch"
    if entry["status"] == "failed":
        return "transport_before_proxy_authentication"
    if normal["ok"] and pinned["ok"]:
        return "no_failure_in_this_comparison"
    if not normal["ok"] and pinned["ok"]:
        return "resolution_related_candidate_requires_server_dns_evidence"
    return "undetermined_requires_core_logs_and_segment_evidence"


def audit(c, cases, output):
    catalog.validate(c)
    required = {"routes", "targets", "evidence", "stability", "fixture_controls"}
    if set(cases) != required or set(cases["routes"]) != {r["id"] for r in c["routes"]}:
        raise Error("audit must explicitly cover every catalog route")
    if set(cases["stability"]) - {"rounds", "interval", "workers", "connect_timeout", "timeout"}:
        raise Error("audit stability cannot exclude or override declared routes")
    for control in cases["fixture_controls"]:
        if not control.get("passed") or not control.get("sha256"):
            raise Error("fixture controls must pass before route testing")
        if hashlib.sha256(Path(control["receipt"]).read_bytes()).hexdigest() != control["sha256"]:
            raise Error("fixture control receipt checksum mismatch")
        if read(control["receipt"]).get("passed") is not True:
            raise Error("fixture receipt does not establish readiness")
    if not cases["fixture_controls"]:
        raise Error("verified controlled fixtures are required")
    cases = copy.deepcopy(cases)
    versions = cases["evidence"]["core_versions"]
    versions["audit_inputs_sha256"] = hashlib.sha256(
        encode({k: v for k, v in cases.items() if k != "evidence"}).encode()
    ).hexdigest()
    versions["audit_source_sha256"] = hashlib.sha256(
        b"".join(
            Path(__file__).with_name(name).read_bytes()
            for name in [
                "audit.py",
                "probe_server.py",
                "exercise.py",
                "verification.py",
                "diagnostics.py",
            ]
        )
    ).hexdigest()
    manifest = {
        **cases["stability"],
        "proxies": {key: spec["proxy"] for key, spec in cases["routes"].items()},
        "targets": cases["targets"],
        "evidence": cases["evidence"],
    }
    validate_cases(manifest)
    for spec in cases["routes"].values():
        if set(spec) != {
            "proxy",
            "pinned_target",
            "egress_url",
            "exercise",
            "benchmark",
            "configuration",
        }:
            raise Error("invalid audit route spec")
        validate_cases({"proxies": {"route": spec["proxy"]}, "targets": [spec["pinned_target"]]})
        if not spec["pinned_target"].get("connect_ip"):
            raise Error("audit requires a pinned comparison with TLS verification")
    for route in c["routes"]:
        udp = cases["routes"][route["id"]]["exercise"].get("udp", {})
        if udp.get("host") == c["hosts"][route["exit_host"]]["address"]:
            raise Error("UDP capability requires an independent target, not host reflection")
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    atomic(output / "input.json", cases)
    atomic(output / "catalog.json", c)
    result = {"completed": False, "routes": {}, "phases": [], "production_changes": False}
    with (output / "audit.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            for route in c["routes"]:
                key = route["id"]
                spec = cases["routes"][key]
                folder = output / key
                folder.mkdir(mode=0o700)
                entry = tcp_entry(c["nodes"][route["node"]])
                normal = probe(key, spec["proxy"], cases["targets"][0], 8, 15)
                pinned = probe(key, spec["proxy"], spec["pinned_target"], 8, 15)
                row = {
                    "entry_tcp": entry,
                    "normal": normal,
                    "pinned": pinned,
                    "configuration": spec["configuration"],
                    "attribution": attribution(entry, normal, pinned, spec["configuration"]),
                }
                atomic(folder / "preflight.json", row)
                result["routes"][key] = row
                print(f"preflight {key}: {row['attribution']}", flush=True)
            result["phases"].append("preflight")
            atomic(output / "result.json", result)
            # Every route is attempted, including routes that failed the preflight.
            for route in c["routes"]:
                key = route["id"]
                spec = cases["routes"][key]
                folder = output / key

                def save_sample(sample, folder=folder):
                    count = len(list(folder.glob("sample-*.json")))
                    path = folder / f"sample-{count + 1:02}.json"
                    if path.exists():
                        raise Error("sample exists; original evidence must not be overwritten")
                    atomic(path, sample)

                try:
                    b = spec["benchmark"]
                    measured = benchmark(
                        spec["proxy"],
                        b["down_url"],
                        b["up_url"],
                        rounds=3,
                        request_timeout=90,
                        connect_ip=b["connect_ip"],
                        on_sample=save_sample,
                    )
                    atomic(folder / "benchmark.json", measured)
                    result["routes"][key]["benchmark_completed"] = True
                except (Error, OSError, ValueError) as error:
                    atomic(
                        folder / "benchmark-tool-error.json", {"error_type": type(error).__name__}
                    )
                    result["routes"][key]["benchmark_completed"] = False
                print(f"benchmark {key}: attempted; first samples retained", flush=True)
                atomic(output / "result.json", result)
            result["phases"].append("benchmark")
            for route in c["routes"]:
                key = route["id"]
                spec = cases["routes"][key]
                diag = {
                    "evidence": cases["evidence"],
                    "routes": {
                        key: {
                            "proxy": spec["proxy"],
                            "targets": cases["targets"],
                            "egress_url": spec["egress_url"],
                            "exercise": spec["exercise"],
                        }
                    },
                }
                try:
                    receipt = diagnose(c, diag, output / key / "diagnosis.json")
                    result["routes"][key]["diagnosis_passed"] = receipt["all_passed"]
                except (Error, OSError, ValueError) as error:
                    atomic(
                        output / key / "diagnosis-tool-error.json",
                        {"error_type": type(error).__name__},
                    )
                    result["routes"][key]["diagnosis_passed"] = False
                print(f"sessions {key}: {result['routes'][key]['diagnosis_passed']}", flush=True)
                atomic(output / "result.json", result)
            result["phases"].append("sessions")
            # No bulk tests are running during this phase. Failed routes remain declared.
            manifest["evidence"] = {**cases["evidence"], "catalog": str(output / "catalog.json")}
            stability = verify(manifest, output / "stability.jsonl")
            result["phases"].append("stability")
            for route in c["routes"]:
                key = route["id"]
                checks = [v for k, v in stability["cases"].items() if k.startswith(key + "/")]
                row = result["routes"][key]
                measurement = output / key / "benchmark.json"
                full = read(measurement) if measurement.exists() else {"samples": []}
                row["qualified"] = (
                    row["configuration"].get("matches") is True
                    and row["normal"]["ok"]
                    and row["pinned"]["ok"]
                    and row.get("diagnosis_passed") is True
                    and len(full["samples"]) == 6
                    and all(s["completed"] for s in full["samples"])
                    and stability["completed"]
                    and stability["elapsed_seconds"] >= 1800
                    and len(checks) >= 2
                    and all(x["checks"] >= 60 and x["failures"] == 0 for x in checks)
                )
            result["completed"] = True
        finally:
            atomic(output / "result.json", result)
    return result
