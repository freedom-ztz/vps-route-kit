import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from vrk import deploy
from vrk.core import verify, credentials, binary
from vrk.util import Error, atomic, redact
from vrk.config import sample


class TransactionTests(unittest.TestCase):
    def test_version_cannot_escape_owned_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "cores"
            with self.assertRaises(Error):
                binary("xray", {"xray": {"version": "../../escaped"}}, root)
            self.assertFalse(root.exists())

    def test_acme_accepts_hostname_address_pointing_to_same_ip(self):
        with tempfile.TemporaryDirectory() as d:
            c = sample()
            c["address"] = "node.example.com"
            c["_bindings"] = []
            ip = [(2, 1, 6, "", ("192.0.2.1", 0))]
            with (
                patch.object(deploy, "ROOT", Path(d)),
                patch.object(deploy, "owned_pids", return_value=set()),
                patch.object(deploy, "socket_rows", return_value=[]),
                patch("vrk.deploy.socket.getaddrinfo", return_value=ip),
            ):
                deploy.preflight(c, {"services": {}})

    def test_tool_version_comment_does_not_require_service_restart(self):
        old = "# Managed by VPS Route Kit 0.1.0\n[Service]\nExecStart=/old/core\n"
        new = "# Managed by VPS Route Kit\n[Service]\nExecStart=/old/core\n"
        self.assertEqual(deploy.unit_runtime(old), deploy.unit_runtime(new))
        self.assertNotEqual(
            deploy.unit_runtime(old), deploy.unit_runtime(new.replace("/old/core", "/new/core"))
        )

    def test_hash_mismatch(self):
        with self.assertRaises(Error):
            verify(b"wrong", "0" * 64)

    def test_credentials_stable(self):
        c = sample()
        fake = SimpleNamespace(
            stdout="PrivateKey: " + "A" * 43 + "\nPassword (PublicKey): " + "B" * 43 + "\n"
        )
        with patch("vrk.core.run", return_value=fake) as r:
            a = credentials(c, {}, "/fake/xray")
            b = credentials(c, a, "/fake/xray")
        self.assertEqual(a, b)
        self.assertEqual(r.call_count, 1)

    def test_atomic_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secret"
            atomic(p, {"x": 1})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_restore_removes_candidate_and_restores_enabled_state(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "data"
            units = Path(d) / "units"
            root.mkdir()
            units.mkdir()
            snapshot = {
                "state": {
                    "generation": "old",
                    "services": {"vrk-xray": "old unit"},
                    "bindings": [],
                },
                "service_state": {"vrk-xray": {"active": True, "enabled": False}},
                "candidate_services": {"vrk-hy-test": "candidate"},
            }
            atomic(
                root / "state.json",
                {"generation": "bad", "services": {"vrk-hy-test": "candidate"}, "bindings": []},
            )
            atomic(units / "vrk-hy-test.service", "candidate")
            with (
                patch.object(deploy, "ROOT", root),
                patch.object(deploy, "UNITS", units),
                patch.object(deploy, "systemctl") as ctl,
            ):
                deploy.restore(snapshot)
            self.assertEqual((root / "current").resolve(), (root / "generations" / "old").resolve())
            self.assertFalse((units / "vrk-hy-test.service").exists())
            self.assertEqual((units / "vrk-xray.service").read_text(), "old unit")
            ctl.assert_any_call("disable", "vrk-xray", check=False)
            ctl.assert_any_call("start", "vrk-xray")

    def test_redaction(self):
        self.assertEqual(
            redact("token secret-token", {"n": {"password": "secret-token"}}), "token [REDACTED]"
        )
