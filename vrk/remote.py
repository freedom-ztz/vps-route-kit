import io
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import uuid
from .core import SOURCE
from .util import Error


def execute(host, argv, *, jump=None, config=None, secrets=None, lock=None):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", host):
        raise Error("invalid SSH host")
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if jump:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", jump):
            raise Error("invalid jump host")
        command += ["-J", jump]
    command += [host]
    temp = "/tmp/vrk-" + uuid.uuid4().hex
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as t:
        for p in [SOURCE / "vrk"]:
            t.add(
                p, arcname=p.name, filter=lambda info: None if "__pycache__" in info.name else info
            )
        launcher = b"from vrk.cli import main\nraise SystemExit(main())\n"
        info = tarfile.TarInfo("vrk.py")
        info.size = len(launcher)
        info.mode = 0o600
        t.addfile(info, io.BytesIO(launcher))
        for path, name in [
            (config, "input.json"),
            (secrets, "input-secrets.json"),
            (lock, "input-lock.json"),
        ]:
            if path:
                t.add(path, arcname=name)
    try:
        p = subprocess.run(
            command + ["umask 077; mkdir " + temp + " && tar -xzf - -C " + temp],
            input=data.getvalue(),
            capture_output=True,
            timeout=120,
        )
        if p.returncode:
            raise Error("SSH upload failed")
        args = ["python3", temp + "/vrk.py", *argv]
        if config:
            args += ["--config", temp + "/input.json"]
        if secrets:
            args += ["--secrets", temp + "/input-secrets.json"]
        if lock:
            args += ["--lock", temp + "/input-lock.json"]
        p = subprocess.run(
            command + [shlex.join(args)], capture_output=True, text=True, timeout=600
        )
        if p.returncode:
            raise Error("remote operation failed: " + p.stderr[-1000:])
        return p.stdout
    finally:
        subprocess.run(command + ["rm -rf -- " + temp], capture_output=True, timeout=30)
