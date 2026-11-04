"""Scoped static Nginx publisher with atomic releases and token-preserving rollback."""

import base64
import fcntl
import grp
import os
from pathlib import Path
import shutil
import socket
import tempfile
import urllib.parse
from .catalog import address, port
from .subscription import FILES, access, origin_url
from .util import Error, atomic, digest, encode, read, run

SYSTEMD_UNITS = Path("/etc/systemd/system")


def quote(value):
    value = str(value)
    if any(c in value for c in "\n\r\x00$"):
        raise Error("unsafe Nginx value")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def validate_bundle(bundle):
    bundle = Path(bundle)
    m = read(bundle / "manifest.json")
    if set(m.get("artifacts", {})) != set(FILES) - {"manifest.json"} or not m.get("routes"):
        raise Error("invalid subscription manifest")
    for f, sha in m["artifacts"].items():
        p = bundle / f
        if (
            p.is_symlink()
            or not p.resolve().is_relative_to(bundle.resolve())
            or not p.is_file()
            or digest(p.read_bytes()) != sha
        ):
            raise Error("subscription artifact checksum mismatch")
    try:
        links = (
            base64.b64decode((bundle / "v2ray.txt").read_text().strip(), validate=True)
            .decode()
            .splitlines()
        )
    except (ValueError, UnicodeError):
        raise Error("invalid V2Ray Base64 subscription") from None
    if not links or not all(x.startswith(("vless://", "hysteria2://")) for x in links):
        raise Error("empty/unsupported V2Ray subscription")
    nodes = read(bundle / "nodes.json")
    if not nodes.get("proxies") or not read(bundle / "desktop.json").get("rules"):
        raise Error("empty subscription rejected")
    return m


def configuration(c, token):
    root = Path(c["root"])
    address(c["domain"])
    address(c.get("listen", "0.0.0.0"))
    port(c["port"])
    if not root.is_absolute() or root == Path("/"):
        raise Error("publication root must be a dedicated absolute directory")
    if urllib.parse.urlsplit(origin_url(c["base_url"])).hostname != c["domain"]:
        raise Error("publication origin and certificate domain differ")
    u = urllib.parse.urlsplit(c["base_url"])
    if (u.port or 443) != c["port"]:
        raise Error("publication origin and port differ")
    lines = [
        f'pid {quote(root / "nginx.pid")};',
        "error_log /dev/null crit;",
        f'user {c.get("user", "www-data")};',
        "events { worker_connections 256; }",
        "http { access_log off; server_tokens off; default_type application/json;",
        f"client_body_temp_path {quote(root / 'tmp' / 'body')};",
        f"proxy_temp_path {quote(root / 'tmp' / 'proxy')};",
        f"fastcgi_temp_path {quote(root / 'tmp' / 'fastcgi')};",
        f"uwsgi_temp_path {quote(root / 'tmp' / 'uwsgi')};",
        f"scgi_temp_path {quote(root / 'tmp' / 'scgi')};",
        f'server {{ listen {quote(c.get("listen", "0.0.0.0") + ":" + str(c["port"]))} ssl;',
        f'server_name {quote(c["domain"])};',
        f'ssl_certificate {quote(c["certificate"])};',
        f'ssl_certificate_key {quote(c["key"])};',
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "autoindex off;",
        'add_header Cache-Control "private, no-store" always;',
        'add_header Referrer-Policy "no-referrer" always;',
        "add_header X-Content-Type-Options nosniff always;",
    ]
    for f in FILES:
        mime = "text/plain" if f.endswith(".txt") else "application/json"
        lines.append(
            f'location = /{token}/{f} {{ default_type {mime}; limit_except GET {{ deny all; }} alias {quote(root / "current" / f)}; }}'
        )
    lines += ["location / { return 404; }", "} }"]
    return "\n".join(lines) + "\n"


def repoint(root, target):
    link = root / (".current-" + str(os.getpid()))
    link.unlink(missing_ok=True)
    link.symlink_to(target)
    os.replace(link, root / "current")


def running(root):
    pidfile = Path(root) / "nginx.pid"
    if not pidfile.exists():
        return False
    value = pidfile.read_text().strip()
    if not value.isdigit() or int(value) < 2:
        return False
    try:
        os.kill(int(value), 0)
    except ProcessLookupError:
        return False
    proc = Path("/proc") / value / "cmdline"
    if proc.exists() and str(Path(root) / "nginx.conf") not in proc.read_bytes().decode(
        errors="replace"
    ):
        raise Error("publication PID belongs to a different process")
    return True


def publish(c, bundle, access_file, allow_candidates=False):
    if os.geteuid() != 0:
        raise Error("static publication requires root on the web host")
    root = Path(c["root"])
    if root.exists() and any(root.iterdir()) and not (root / "owner.json").exists():
        raise Error("publication root is not owned by this project")
    token = access(access_file)
    config = configuration(c, token)
    bundle = Path(bundle)
    m = validate_bundle(bundle)
    if m.get("candidate_only") and not allow_candidates:
        raise Error("candidate subscriptions require --allow-candidates on isolated hosts")
    for field in ("certificate", "key"):
        if not Path(c[field]).is_file():
            raise Error("publication certificate/key missing")
    match = run(["openssl", "x509", "-in", c["certificate"], "-noout", "-checkhost", c["domain"]])
    if "does match certificate" not in match.stdout or "does NOT match" in match.stdout:
        raise Error("publication certificate does not cover domain")
    run(["openssl", "x509", "-in", c["certificate"], "-noout", "-checkend", "0"])
    user = c.get("user", "www-data")
    if not user.replace("-", "").replace("_", "").isalnum():
        raise Error("invalid Nginx worker user")
    gid = grp.getgrnam(user).gr_gid
    root.mkdir(parents=True, exist_ok=True)
    os.chown(root, 0, gid)
    root.chmod(0o750)
    with (root / "publish.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not running(root):
            with socket.socket() as s:
                try:
                    s.bind((c.get("listen", "0.0.0.0"), c["port"]))
                except OSError:
                    raise Error("publication port occupied; existing listener untouched") from None
        state = read(root / "owner.json") if (root / "owner.json").exists() else {}
        if state and state["config"] != c:
            raise Error("web listener settings changed; reconcile explicitly before publication")
        if not state:
            atomic(root / "owner.json", {"config": c, "revision": None, "previous": None})
        (root / "tmp").mkdir(mode=0o750, exist_ok=True)
        os.chown(root / "tmp", 0, gid)
        (root / "tmp").chmod(0o750)
        releases = root / "releases"
        releases.mkdir(mode=0o750, exist_ok=True)
        os.chown(releases, 0, gid)
        releases.chmod(0o750)
        temp = Path(tempfile.mkdtemp(prefix=".candidate-", dir=releases))
        old_target = os.readlink(root / "current") if (root / "current").is_symlink() else None
        old_config = (root / "nginx.conf").read_text() if (root / "nginx.conf").exists() else None
        nginx = c.get("nginx", "/usr/sbin/nginx")
        try:
            for f in FILES:
                dest = temp / f
                dest.parent.mkdir(mode=0o750, exist_ok=True)
                shutil.copyfile(bundle / f, dest)
            # Rollback keeps the current access token; old tokens must not be re-enabled.
            for f in ("desktop.json", "openwrt-example.json"):
                document = read(temp / f)

                def urls(v):
                    if isinstance(v, dict):
                        return {k: urls(x) for k, x in v.items()}
                    if isinstance(v, list):
                        return [urls(x) for x in v]
                    if isinstance(v, str) and v.startswith(c["base_url"].rstrip("/") + "/"):
                        u = urllib.parse.urlsplit(v)
                        parts = u.path.strip("/").split("/")
                        if len(parts) >= 2 and len(parts[0]) == 43:
                            return (
                                c["base_url"].rstrip("/") + "/" + token + "/" + "/".join(parts[1:])
                            )
                    return v

                atomic(temp / f, urls(document))
            m["artifacts"] = {
                f: digest((temp / f).read_bytes()) for f in FILES if f != "manifest.json"
            }
            m.pop("revision", None)
            m["revision"] = digest(encode(m))[:20]
            atomic(temp / "manifest.json", m)
            for p in [temp, *temp.rglob("*")]:
                os.chown(p, 0, gid)
                p.chmod(0o750 if p.is_dir() else 0o640)
            target = releases / m["revision"]
            if target.exists():
                validate_bundle(target)
                shutil.rmtree(temp)
            else:
                os.replace(temp, target)
            for f in FILES:
                run(["runuser", "-u", user, "--", "test", "-r", target / f])
            repoint(root, "releases/" + target.name)
            atomic(root / "nginx.conf", config)
            test = run([nginx, "-t", "-p", str(root) + "/", "-c", root / "nginx.conf"], check=False)
            atomic(root / "validation.log", test.stdout + test.stderr)
            if test.returncode:
                raise Error("Nginx validation failed; inspect private publication validation.log")
            service_name = "vrk-subscription-" + digest(str(root))[:10] + ".service"
            service_file = SYSTEMD_UNITS / service_name
            command = " ".join(
                quote(x).replace("%", "%%")
                for x in [nginx, "-p", str(root) + "/", "-c", root / "nginx.conf"]
            )
            service = (
                "# Managed by VPS Route Kit static subscriptions\n[Unit]\nDescription=VPS Route Kit static subscription\n"
                "After=network-online.target\n[Service]\nType=forking\n"
                + "PIDFile="
                + str(root / "nginx.pid")
                + "\nExecStart="
                + command
                + "\nExecReload="
                + command
                + " -s reload\nExecStop="
                + command
                + " -s quit\n"
                + "Restart=on-failure\n[Install]\nWantedBy=multi-user.target\n"
            )
            if service_file.exists() and service_file.read_text() != service:
                raise Error("subscription systemd unit was edited externally")
            if running(root) and not service_file.exists():
                raise Error(
                    "standalone Nginx already running; reconcile its lifecycle before publishing"
                )
            atomic(service_file, service, 0o644)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", service_name])
            active = run(["systemctl", "is-active", service_name], check=False).returncode == 0
            run(["systemctl", "reload" if active else "start", service_name])
            atomic(
                root / "owner.json",
                {"config": c, "revision": m["revision"], "previous": old_target},
            )
        except BaseException:
            if old_target:
                repoint(root, old_target)
            else:
                (root / "current").unlink(missing_ok=True)
            if old_config is not None:
                atomic(root / "nginx.conf", old_config)
            else:
                (root / "nginx.conf").unlink(missing_ok=True)
            raise
        finally:
            if temp.exists():
                shutil.rmtree(temp)
    return {"revision": m["revision"], "published": True, "candidate_only": m["candidate_only"]}


def rollback(c, access_file, allow_candidates=False):
    state = read(Path(c["root"]) / "owner.json")
    previous = state.get("previous")
    if not previous or not previous.startswith("releases/") or ".." in previous:
        raise Error("no previous subscription release")
    return publish(c, Path(c["root"]) / previous, access_file, allow_candidates)
