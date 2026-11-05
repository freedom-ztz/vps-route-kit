import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from vrk.util import Error
from vrk.verification import probe, verify, validate_cases


def cases():
    return {
        "proxies": {"test": "socks5h://127.0.0.1:10808"},
        "targets": [{"name": "controlled", "url": "https://health.example.com/", "expect": 204}],
        "rounds": 2,
        "interval": 0,
    }


class VerificationTests(unittest.TestCase):
    def test_fixed_ip_changes_connection_destination_without_disabling_tls(self):
        target = {**cases()["targets"][0], "connect_ip": "192.0.2.10"}
        c = cases()
        c["targets"] = [target]
        validate_cases(c)
        with patch(
            "vrk.verification.run",
            return_value=SimpleNamespace(returncode=0, stdout='{"http_code":204}', stderr=""),
        ) as run:
            self.assertTrue(probe("test", c["proxies"]["test"], target, 8, 12)["ok"])
        args = run.call_args.args[0]
        self.assertEqual(
            args[args.index("--connect-to") + 1], "health.example.com:443:192.0.2.10:443"
        )
        self.assertIn(target["url"], args)
        self.assertNotIn("--insecure", args)
        self.assertNotIn("-k", args)

    def test_no_proxy_environment_cannot_bypass_explicit_proxy(self):
        result = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"http_code": 204, "url_effective": "do not retain full URL", "local_port": 40000}
            ),
            stderr="",
        )
        with patch("vrk.verification.run", return_value=result) as run:
            sample = probe("test", "socks5h://127.0.0.1:10808", cases()["targets"][0], 8, 12)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--noproxy") + 1], "")
        self.assertTrue(sample["ok"])
        self.assertNotIn("url_effective", sample["metrics"])
        run.assert_called_once()

    def test_first_failure_is_not_hidden_by_later_success(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "verify.jsonl"
            failed = {"proxy": "test", "target": "controlled", "ok": False, "exit": 35}
            good = {"proxy": "test", "target": "controlled", "ok": True, "exit": 0}
            with patch("vrk.verification.probe", side_effect=[failed, good]):
                result = verify(cases(), output)
            self.assertEqual(result["checks"], 2)
            self.assertEqual(result["failures"], 1)
            self.assertFalse(result["all_declared_passed"])
            self.assertEqual(len(output.read_text().splitlines()), 2)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(Error):
                verify(cases(), output)

    def test_excluded_candidate_remains_visible_and_blocks_overall_pass(self):
        c = cases()
        c["proxies"]["bad"] = "socks5h://127.0.0.1:10809"
        c["excluded"] = {"bad": "UDP path blocked"}
        c["rounds"] = 1
        with (
            tempfile.TemporaryDirectory() as d,
            patch(
                "vrk.verification.probe",
                return_value={"proxy": "test", "target": "controlled", "ok": True},
            ),
        ):
            result = verify(c, Path(d) / "result")
        self.assertTrue(result["active_cases_passed"])
        self.assertFalse(result["all_declared_passed"])
        self.assertEqual(result["excluded"], c["excluded"])

    def test_interruption_preserves_incomplete_summary(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "result"
            with (
                patch("vrk.verification.probe", side_effect=KeyboardInterrupt),
                self.assertRaises(KeyboardInterrupt),
            ):
                verify(cases(), out)
            result = json.loads(Path(str(out) + ".summary.json").read_text())
            self.assertFalse(result["completed"])
            self.assertFalse(result["all_declared_passed"])

    def test_invalid_manifest(self):
        for update in [
            {"rounds": 0},
            {"interval": float("nan")},
            {"excluded": {"test": "all cases removed"}},
            {"targets": [{"name": "http", "url": "http://example.com", "expect": 200}]},
        ]:
            c = cases()
            c.update(update)
            with self.subTest(update=update), self.assertRaises(Error):
                validate_cases(c)

    def test_transport_failure_does_not_claim_exact_cause(self):
        with patch(
            "vrk.verification.run",
            return_value=SimpleNamespace(
                returncode=35, stdout='{"http_code":0}', stderr="TLS setup failed"
            ),
        ):
            s = probe("test", cases()["proxies"]["test"], cases()["targets"][0], 8, 12)
        self.assertFalse(s["ok"])
        self.assertEqual(s["failure"], "proxy_or_transport")
