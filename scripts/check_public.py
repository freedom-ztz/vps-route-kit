"""Reject private artifacts and non-documentation public addresses in tracked files."""

from pathlib import Path
import ipaddress
import json
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
r = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
errors = []
for name in r.stdout.decode().split("\0"):
    if not name:
        continue
    p = root / name
    if p.suffix in (".pem", ".key", ".crt") or ".private/" in name:
        errors.append(name + ": private artifact")
    try:
        text = p.read_text()
    except UnicodeDecodeError:
        errors.append(name + ": unexpected binary")
        continue
    if (
        "-----BEGIN " + "PRIVATE KEY-----" in text
        or "-----BEGIN " + "OPENSSH PRIVATE KEY-----" in text
    ):
        errors.append(name + ": private key")
    if p.suffix in (".json",):

        def inspect(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if (
                        key in ("password", "private_key", "uuid")
                        and isinstance(item, str)
                        and item
                        and item != "..."
                        and not item.startswith(("REPLACE_", "EXAMPLE_"))
                    ):
                        errors.append(name + ": credential value in JSON")
                    inspect(item)
            elif isinstance(value, list):
                for item in value:
                    inspect(item)

        try:
            inspect(json.loads(text))
        except ValueError:
            errors.append(name + ": invalid JSON")
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_global:
            errors.append(name + ": routable IP address")
    if re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", text):
        errors.append(name + ": access key")
if errors:
    print("\n".join(sorted(set(errors))), file=sys.stderr)
    sys.exit(1)
print("Public artifact check passed (also review diffs before publishing)")
