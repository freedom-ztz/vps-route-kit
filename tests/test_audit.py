import copy
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest

from vrk.audit import audit, attribution
from vrk.util import atomic, read, Error
from test_subscription import inventory


class AuditTests(unittest.TestCase):
    def setup_case(self, folder):
        c = inventory()
        other = copy.deepcopy(c["routes"][0])
        other["id"] = "other"
        c["routes"].append(other)
        control = Path(folder) / "control.json"
        atomic(control, {"passed": True})
        targets = [{"name": "controlled", "url": "https://example.com/health", "expect": 204}]
        spec = {
            "proxy": "socks5h://127.0.0.1:10808",
            "pinned_target": {**targets[0], "connect_ip": "192.0.2.30"},
            "egress_url": "https://example.com/egress",
            "exercise": {
                "stream_url": "https://example.com/stream",
                "idle_url": "https://example.com/health",
                "download_url": "https://example.com/down",
                "upload_url": "https://example.com/up",
                "udp": {"host": "192.0.2.30", "port": 18445},
            },
            "benchmark": {
                "down_url": "https://example.com/down",
                "up_url": "https://example.com/up",
                "connect_ip": "192.0.2.30",
            },
            "configuration": {"matches": True},
        }
        return c, {
            "routes": {k: copy.deepcopy(spec) for k in ["test", "other"]},
            "targets": targets,
            "evidence": {"batch_id": "test", "core_versions": {"mihomo": "test"}},
            "stability": {"rounds": 60, "interval": 30},
            "fixture_controls": [
                {
                    "passed": True,
                    "receipt": str(control),
                    "sha256": hashlib.sha256(control.read_bytes()).hexdigest(),
                }
            ],
        }

    def test_failed_node_does_not_skip_its_speed_test_or_another_node(self):
        calls = []

        def measured(proxy, down, up, **kwargs):
            samples = [{"completed": True, "direction": "down", "round": i} for i in range(6)]
            for s in samples:
                kwargs["on_sample"](s)
            calls.append(proxy)
            return {"samples": samples}

        with tempfile.TemporaryDirectory() as folder:
            c, spec = self.setup_case(folder)
            stability = {
                "completed": True,
                "elapsed_seconds": 1800,
                "cases": {
                    "test/a": {"checks": 60, "failures": 1},
                    "test/b": {"checks": 60, "failures": 0},
                    "other/a": {"checks": 60, "failures": 0},
                    "other/b": {"checks": 60, "failures": 0},
                },
            }
            with (
                patch("vrk.audit.tcp_entry", return_value={"status": "passed"}),
                patch(
                    "vrk.audit.probe",
                    side_effect=[{"ok": False}, {"ok": False}, {"ok": True}, {"ok": True}],
                ),
                patch("vrk.audit.benchmark", side_effect=measured),
                patch(
                    "vrk.audit.diagnose", side_effect=[{"all_passed": False}, {"all_passed": True}]
                ),
                patch("vrk.audit.verify", return_value=stability),
            ):
                result = audit(c, spec, Path(folder) / "output")
            self.assertTrue(result["completed"])
            self.assertFalse(result["routes"]["test"]["qualified"])
            self.assertTrue(result["routes"]["other"]["qualified"])
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(list((Path(folder) / "output/test").glob("sample-*.json"))), 6)
            with self.assertRaises(FileExistsError):
                audit(c, spec, Path(folder) / "output")

    def test_reflexive_udp_is_not_a_proxy_capability_test(self):
        with tempfile.TemporaryDirectory() as folder:
            c, spec = self.setup_case(folder)
            spec["routes"]["test"]["exercise"]["udp"] = {
                "host": c["hosts"]["exit"]["address"],
                "port": 18445,
            }
            with self.assertRaisesRegex(Error, "independent target"):
                audit(c, spec, Path(folder) / "output")

    def test_resolution_difference_is_only_a_candidate_cause(self):
        self.assertEqual(
            attribution({"status": "passed"}, {"ok": False}, {"ok": True}, {"matches": True}),
            "resolution_related_candidate_requires_server_dns_evidence",
        )

    def test_session_coverage_is_required_before_any_network_probe(self):
        for omitted in ("idle_url", "stream_url", "udp", "udp-null"):
            with self.subTest(omitted=omitted), tempfile.TemporaryDirectory() as folder:
                c, spec = self.setup_case(folder)
                if omitted == "udp-null":
                    spec["routes"]["test"]["exercise"]["udp"] = None
                else:
                    del spec["routes"]["test"]["exercise"][omitted]
                with patch("vrk.audit.tcp_entry", side_effect=AssertionError("network I/O")):
                    with self.assertRaises(Error):
                        audit(c, spec, Path(folder) / "output")
                self.assertFalse((Path(folder) / "output").exists())

    def test_proxy_success_requires_investigation_of_a_failed_direct_entry_probe(self):
        for normal, pinned in [(True, True), (False, True), (True, False)]:
            with self.subTest(normal=normal, pinned=pinned):
                self.assertEqual(
                    attribution(
                        {"status": "failed"},
                        {"ok": normal},
                        {"ok": pinned},
                        {"matches": True},
                    ),
                    "entry_probe_and_proxy_disagree_requires_path_and_timing_evidence",
                )
