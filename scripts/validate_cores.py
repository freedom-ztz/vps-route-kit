"""Validate generated Xray configs against the locked official core in CI."""

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vrk.config import sample, validate
from vrk.core import binary, credentials, LOCK
from vrk.render import render
from vrk.util import read, run

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    core = binary("xray", read(LOCK), root / "cores")
    c = validate(sample())
    s = credentials(c, {}, core)
    files, _ = render(c, s, str(root))
    p = root / "xray.json"
    p.write_text(files["xray.json"])
    run([core, "run", "-test", "-config", p])
    print("Locked Xray validates Vision + REALITY + XHTTP configuration")
