import io
import tarfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from vrk.remote import execute
from vrk.util import Error


class RemoteTests(unittest.TestCase):
    def test_archive_has_launcher_and_lock(self):
        calls = []

        def fake(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        with patch("vrk.remote.subprocess.run", side_effect=fake):
            self.assertEqual(execute("root@example.com", ["status"]), "ok")
        with tarfile.open(fileobj=io.BytesIO(calls[0][1]["input"]), mode="r:gz") as archive:
            self.assertIn("vrk.py", archive.getnames())
            self.assertIn("vrk/versions.lock.json", archive.getnames())
        self.assertFalse(any("StrictHostKeyChecking=no" in str(c) for c in calls))

    def test_shell_target_rejected(self):
        with self.assertRaises(Error):
            execute("host;touch /tmp/bad", ["status"])
