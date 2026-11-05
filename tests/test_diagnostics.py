import unittest
from unittest.mock import patch
from vrk.diagnostics import cpu_usage, benchmark
from vrk.util import Error


class DiagnosticsTests(unittest.TestCase):
    def test_cpu_delta(self):
        a = {"time": 10, "hz": 100, "processes": {"1": {"comm": "xray", "ticks": 20}}}
        b = {"time": 12, "hz": 100, "processes": {"1": {"comm": "xray", "ticks": 70}}}
        self.assertEqual(cpu_usage(a, b)[0]["percent_one_core"], 25)

    def test_missing_cpu_is_not_zero(self):
        self.assertIsNone(cpu_usage(None, None))

    def test_benchmark_rejects_non_tls_endpoint(self):
        with self.assertRaises(Error):
            benchmark("socks5h://127.0.0.1:10808", "http://example.com", "https://example.com")

    def test_benchmark_forces_proxy_and_preserves_failure_reason(self):
        import json
        from types import SimpleNamespace

        results = [
            SimpleNamespace(
                returncode=28,
                stdout=json.dumps(
                    {"http_code": 200, "size_download": 1000, "time_appconnect": 1.2}
                ),
                stderr="transfer timeout",
            ),
            SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {"http_code": 200, "size_upload": 8000000, "time_appconnect": 0.5}
                ),
                stderr="",
            ),
        ]
        captured = []
        with patch("vrk.diagnostics.run", side_effect=results) as run:
            r = benchmark(
                "socks5h://127.0.0.1:10808",
                "https://example.com/down",
                "https://example.com/up",
                rounds=1,
                on_sample=captured.append,
                connect_ip="192.0.2.10",
            )
        self.assertFalse(r["samples"][0]["completed"])
        self.assertIsNone(r["qualified_median_mbps"]["down"])
        self.assertEqual(r["completion"]["down"], {"expected": 1, "completed": 0})
        self.assertEqual(r["samples"][0]["error"], "transfer timeout")
        self.assertTrue(r["samples"][1]["completed"])
        self.assertEqual(len(captured), 2)
        self.assertFalse(captured[0]["completed"])
        self.assertEqual(captured[0]["dns_mode"], "fixed_ip")
        for call in run.call_args_list:
            args = call.args[0]
            self.assertEqual(args[args.index("--noproxy") + 1], "")
            self.assertEqual(args[args.index("--connect-to") + 1], "example.com:443:192.0.2.10:443")

    def test_cli_refuses_to_overwrite_a_previous_speed_result(self):
        import contextlib
        import io
        import tempfile
        from pathlib import Path
        from vrk.cli import main

        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "old.json"
            output.write_text("original failure evidence")
            with (
                patch("vrk.diagnostics.benchmark") as measured,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = main(
                    [
                        "benchmark",
                        "--proxy",
                        "socks5h://127.0.0.1:10808",
                        "--down-url",
                        "https://example.com/down",
                        "--up-url",
                        "https://example.com/up",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(status, 1)
            measured.assert_not_called()
            self.assertEqual(output.read_text(), "original failure evidence")
