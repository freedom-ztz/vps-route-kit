import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import tarfile
import urllib.request
import uuid
import zipfile
from .util import Error, atomic, read, run

SOURCE = Path(__file__).resolve().parent.parent
LOCK = Path(__file__).with_name("versions.lock.json")


def architecture():
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if not arch:
        raise Error("unsupported architecture")
    return arch


def verify(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise Error("download SHA-256 mismatch")


def binary(component, lock, base=Path("/opt/vrk")):
    official = {
        "xray": "XTLS/Xray-core",
        "hysteria": "HyNetworks/hysteria",
        "realm": "zhboner/realm",
    }
    if component not in official:
        raise Error("unknown core component")
    spec = lock[component]
    if not isinstance(spec.get("version"), str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){2}(?:[.-][A-Za-z0-9]+)*", spec["version"]
    ):
        raise Error("invalid locked version")
    asset = spec["assets"][architecture()]
    if not isinstance(asset.get("sha256"), str) or not re.fullmatch(
        r"[a-f0-9]{64}", asset["sha256"]
    ):
        raise Error("invalid locked SHA-256")
    if not asset["url"].startswith(
        "https://github.com/" + official[component] + "/releases/download/"
    ):
        raise Error("asset must use official GitHub HTTPS release")
    target = base / "bin" / component / spec["version"] / component
    for directory in [base, base / "bin", base / "bin" / component, target.parent]:
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o755)
    if target.exists():
        receipt = read(target.parent / "receipt.json")
        verify(target.read_bytes(), receipt["binary_sha256"])
        if receipt["asset_sha256"] != asset["sha256"]:
            raise Error("cached asset differs from lock")
        return target
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "vps-route-kit/0.1"})
    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read(150_000_001)
    if len(data) > 150_000_000:
        raise Error("asset too large")
    verify(data, asset["sha256"])
    if component == "xray":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = z.open("xray").read(150_000_001)
    elif component == "realm":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            members = [m for m in t.getmembers() if Path(m.name).name == "realm" and m.isfile()]
            if len(members) != 1:
                raise Error("invalid realm archive")
            data = t.extractfile(members[0]).read(150_000_001)
    if len(data) > 150_000_000:
        raise Error("unpacked binary too large")
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(".new")
    temp.write_bytes(data)
    temp.chmod(0o755)
    os.replace(temp, target)
    atomic(
        target.parent / "receipt.json",
        {
            "asset_sha256": asset["sha256"],
            "binary_sha256": hashlib.sha256(data).hexdigest(),
            "url": asset["url"],
        },
    )
    return target


def credentials(c, existing, xray):
    if not isinstance(existing, dict):
        raise Error("secrets must be an object")
    result = json.loads(json.dumps(existing))
    for l in c["listeners"]:
        sec = result.setdefault(l["secret"], {})
        if not isinstance(sec, dict):
            raise Error("credential entry must be an object")
        if l["protocol"] == "hysteria2":
            sec.setdefault("password", secrets.token_urlsafe(36))
        elif "private_key" not in sec:
            output = run([xray, "x25519"]).stdout
            values = {
                k.strip().lower().replace(" ", ""): v.strip()
                for k, v in (line.split(":", 1) for line in output.splitlines() if ":" in line)
            }
            private = values.get("privatekey")
            public = values.get(
                "publickey", values.get("password", values.get("password(publickey)"))
            )
            if not private or not public:
                raise Error("unknown xray x25519 output format")
            sec.update(private_key=private, public_key=public)
        if l["protocol"] != "hysteria2":
            sec.setdefault("uuid", str(uuid.uuid4()))
            sec.setdefault("short_id", secrets.token_hex(8))
            try:
                uuid.UUID(sec["uuid"])
            except (ValueError, TypeError, AttributeError):
                raise Error("invalid listener UUID")
            for key in ("private_key", "public_key"):
                if not isinstance(sec.get(key), str) or not re.fullmatch(
                    r"[A-Za-z0-9_-]{43}", sec[key]
                ):
                    raise Error("invalid listener REALITY key")
            if not isinstance(sec.get("short_id"), str) or not re.fullmatch(
                r"(?:[a-fA-F0-9]{2}){0,8}", sec["short_id"]
            ):
                raise Error("invalid listener short_id")
        elif not isinstance(sec.get("password"), str) or not sec["password"]:
            raise Error("listener password must be a nonempty string")
    for key, n in c["nodes"].items():
        sec = result.get(n["secret"], {})
        if not isinstance(sec, dict):
            raise Error("node credential must be an object")
        if n["protocol"] == "hysteria2":
            if not isinstance(sec.get("password"), str) or not sec.get("password"):
                raise Error(f"missing password for node {key}")
        else:
            try:
                uuid.UUID(sec["uuid"])
            except (KeyError, ValueError):
                raise Error(f"missing/invalid UUID for node {key}")
    return result
