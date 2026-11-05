import ipaddress
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class PublicArtifactCheckTests(unittest.TestCase):
    def check_fixture(self, text):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            script = root / "scripts/check_public.py"
            shutil.copy2(Path(__file__).resolve().parents[1] / "scripts/check_public.py", script)
            (root / "fixture.md").write_text(text)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
            return subprocess.run([sys.executable, str(script)], capture_output=True, text=True)

    def test_multicast_is_not_a_private_public_vps_address(self):
        result = self.check_fixture("Invalid DNS test case: 224.0.0.1\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_unicast_is_still_rejected(self):
        # Generate a synthetic address without embedding a routable literal in the repository.
        candidate = str(ipaddress.IPv4Address((1 << 24) + (1 << 16) + (1 << 8) + 2))
        result = self.check_fixture("Unintended node address: " + candidate + "\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("fixture.md: routable IP address", result.stderr)
