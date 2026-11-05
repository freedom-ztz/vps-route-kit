"""Download the pinned compatibility-test core; never installs a VPS service."""

import argparse
import gzip
import hashlib
from pathlib import Path
import urllib.request

URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-compatible-v1.19.32.gz"
SHA256 = "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"
p = argparse.ArgumentParser()
p.add_argument("--output", required=True)
a = p.parse_args()
with urllib.request.urlopen(URL, timeout=90) as r:
    data = r.read(50_000_001)
if len(data) > 50_000_000 or hashlib.sha256(data).hexdigest() != SHA256:
    raise SystemExit("Test-core checksum mismatch")
out = Path(a.output)
if out.exists():
    raise SystemExit("Output exists")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(gzip.decompress(data))
out.chmod(0o700)
print("Pinned Mihomo 1.19.32 compatible test core ready")
