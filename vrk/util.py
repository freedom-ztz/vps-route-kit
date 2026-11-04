import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


class Error(Exception):
    pass


def run(args, *, check=True, **kwargs):
    try:
        p = subprocess.run(
            [str(a) for a in args],
            capture_output=True,
            text=True,
            timeout=kwargs.pop("timeout", 120),
            **kwargs,
        )
    except subprocess.TimeoutExpired:
        raise Error(f"{Path(str(args[0])).name} timed out") from None
    if check and p.returncode:
        # Core diagnostics can contain authentication material. Keep them in private files.
        raise Error(
            f"{Path(str(args[0])).name} failed (exit {p.returncode}); use doctor/logs for redacted diagnostics"
        )
    return p


def read(path):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise Error("duplicate JSON key: " + k)
            result[k] = v
        return result

    return json.loads(Path(path).read_text(), object_pairs_hook=pairs)


def encode(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def atomic(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(data if isinstance(data, str) else encode(data))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def digest(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def redact(text, secrets):
    values = []
    for v in secrets.values():
        if isinstance(v, dict):
            values.extend(str(x) for k, x in v.items() if k not in ("public_key",) and x)
    for value in sorted(values, key=len, reverse=True):
        if len(value) > 3:
            text = text.replace(value, "[REDACTED]")
    return text
