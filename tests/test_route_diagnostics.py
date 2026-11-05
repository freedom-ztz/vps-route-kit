import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import unittest

from vrk.route_diagnostics import diagnose, egress
from test_subscription import inventory


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
