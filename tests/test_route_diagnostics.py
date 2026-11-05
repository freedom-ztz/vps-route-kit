import json
from pathlib import Path
import socket
import subprocess
import tempfile
from unittest.mock import patch
import unittest

from vrk.route_diagnostics import clock_evidence, diagnose, egress, segment
from test_subscription import inventory


class SegmentEvidenceTests(unittest.TestCase):
    def test_clock_offset_excludes_remote_probe_work_without_assuming_equal_latency(self):
        clock = clock_evidence(
            100, 110, 10, {"started": 105.2, "ended": 114.8, "probe_seconds": 9.6}
        )
        self.assertTrue(clock["comparable"])
        self.assertAlmostEqual(clock["offset_seconds_min"], 4.8)
        self.assertAlmostEqual(clock["offset_seconds_max"], 5.2)

    def test_clock_step_cannot_be_used_to_align_logs(self):
        clock = clock_evidence(100, 110, 10, {"started": 105.2, "ended": 120, "probe_seconds": 9.6})
        self.assertFalse(clock["comparable"])
        self.assertIsNone(clock["offset_seconds_min"])

    def test_local_tcp_probe_records_actual_probe_time_separately_from_execution(self):
        c = inventory()
        destination = next(iter(c["hosts"]))
        c["hosts"][destination]["address"] = "127.0.0.1"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            receipt = segment(
                c,
                {
                    "from": "local",
                    "to": destination,
                    "port": listener.getsockname()[1],
                    "transport": "tcp",
                },
            )
        self.assertEqual(receipt["status"], "passed")
        self.assertGreaterEqual(receipt["elapsed"], receipt["probe_seconds"])
        self.assertTrue(receipt["clock"]["comparable"])
        self.assertLessEqual(receipt["clock"]["offset_seconds_min"], 0)
        self.assertGreaterEqual(receipt["clock"]["offset_seconds_max"], 0)

    def test_failed_ssh_is_unmeasured_instead_of_a_failed_target_path(self):
        c = inventory()
        origin = next(iter(c["hosts"]))
        c["hosts"][origin]["ssh"] = "example-host"
        with patch(
            "vrk.route_diagnostics.run",
            return_value=subprocess.CompletedProcess([], 255, "", "SSH authentication failed"),
        ):
            receipt = segment(c, {"from": origin, "to": origin, "port": 443, "transport": "tcp"})
        self.assertEqual(receipt["status"], "unmeasured")
        self.assertEqual(receipt["execution_exit"], 255)
        self.assertNotIn("authentication", json.dumps(receipt))

    def test_remote_socket_failure_retains_probe_cause_and_clock_receipt(self):
        c = inventory()
        origin = next(iter(c["hosts"]))
        c["hosts"][origin]["ssh"] = "example-host"
        remote = {
            "started": 105.2,
            "ended": 114.8,
            "probe_seconds": 9.6,
            "ok": False,
            "error_type": "TimeoutError",
        }
        with (
            patch("vrk.route_diagnostics.time.time", side_effect=[100, 110]),
            patch("vrk.route_diagnostics.time.monotonic", side_effect=[200, 210]),
            patch(
                "vrk.route_diagnostics.run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps(remote), ""),
            ),
        ):
            receipt = segment(c, {"from": origin, "to": origin, "port": 443, "transport": "tcp"})
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["error_type"], "TimeoutError")
        self.assertEqual(receipt["probe_seconds"], 9.6)
        self.assertAlmostEqual(receipt["clock"]["offset_seconds_min"], 4.8)


class EgressEvidenceTests(unittest.TestCase):
    def response(self, body, exit=0, error="", status=200):
        meta = {
            "http_code": status,
            "local_port": 52123,
            "time_total": 5.01,
            "url_effective": "https://private.example/egress",
        }
        return subprocess.CompletedProcess([], exit, body + "\n" + json.dumps(meta), error)

    def test_failed_egress_keeps_first_curl_error_and_local_port(self):
        result = self.response("", 35, "TLS connection closed", 0)
        with patch("vrk.route_diagnostics.run", return_value=result) as call:
            receipt = egress("socks5h://127.0.0.1:1080", "https://private.example/egress")
        self.assertEqual(call.call_count, 1)
        self.assertIsNone(receipt["ip"])
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["exit"], 35)
        self.assertEqual(receipt["meta"]["local_port"], 52123)
        self.assertEqual(receipt["error"], "TLS connection closed")
        self.assertNotIn("url_effective", receipt["meta"])

    def test_successful_plain_or_json_ipv4_has_evidence_without_body(self):
        for body in ["192.0.2.20", '{"ip":"192.0.2.20"}']:
            with (
                self.subTest(body=body),
                patch("vrk.route_diagnostics.run", return_value=self.response(body)),
            ):
                receipt = egress("socks5h://127.0.0.1:1080", "https://private.example/egress")
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["ip"], "192.0.2.20")
            self.assertNotIn("body", receipt)

    def test_invalid_body_is_a_probe_failure_without_saving_content(self):
        with patch(
            "vrk.route_diagnostics.run", return_value=self.response('{"token":"PRIVATE_RESPONSE"}')
        ):
            receipt = egress("socks5h://127.0.0.1:1080", "https://private.example/egress")
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["failure"], "invalid_egress_ipv4")
        self.assertNotIn("PRIVATE_RESPONSE", json.dumps(receipt))

    def test_successful_https_does_not_hide_failed_egress_request(self):
        failure = {
            "ip": None,
            "ok": False,
            "exit": 35,
            "error": "TLS connection closed",
            "meta": {"local_port": 52123},
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "diagnosis.json"
            cases = {
                "routes": {
                    "test": {
                        "proxy": "socks5h://127.0.0.1:1080",
                        "targets": [
                            {
                                "name": "controlled",
                                "url": "https://example.com/health",
                                "expect": 204,
                            }
                        ],
                        "egress_url": "https://example.com/egress",
                    }
                }
            }
            with (
                patch("vrk.route_diagnostics.probe", return_value={"ok": True}),
                patch("vrk.route_diagnostics.egress", return_value=failure),
            ):
                result = diagnose(inventory(), cases, path)
            saved = json.loads(path.read_text())["routes"]["test"]
        self.assertFalse(result["all_passed"])
        self.assertIsNone(saved["exit_ipv4"])
        self.assertEqual(saved["egress_probe"]["exit"], 35)
