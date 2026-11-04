"""Scoped static Nginx publisher with atomic releases and token-preserving rollback."""

import base64
import fcntl
import grp
import os
from pathlib import Path
import shutil
import socket
import tempfile
import re
import time
import urllib.parse
from .catalog import address, port
from .subscription import FILES, access, origin_url
from .util import Error, atomic, digest, encode, read, run

SYSTEMD_UNITS = Path("/etc/systemd/system")
LOGROTATE = Path("/etc/logrotate.d")


def quote(value):
    value = str(value)
    if any(c in value for c in "\n\r\x00$"):
        raise Error("unsafe Nginx value")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def validate_bundle(bundle):
    bundle = Path(bundle)
    m = read(bundle / "manifest.json")
    if m.get("access_mode") == "public":
        from .config import name as check_name

        check_name(m.get("name"))
        if not re.fullmatch("[a-f0-9]{20}", m.get("rule_version", "")):
            raise Error("invalid rule version")
    artifacts = m.get("artifacts", {})
    formats = m.get("selected_formats", ["clash", "v2ray"])
    required = set()
    if "clash" in formats:
        required.update(
            {
                "desktop.json",
                "nodes.json",
                "openwrt-example.json",
                "rules/domains.txt",
                "rules/cidrs.txt",
            }
        )
    if "v2ray" in formats:
        required.add("v2ray.txt")
    if (
        not required
        or set(formats) - {"clash", "v2ray"}
        or set(artifacts) != required
        or not m.get("routes")
    ):
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
    if "v2ray" in formats:
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
    if "clash" in formats:
        nodes = read(bundle / "nodes.json")
        if not nodes.get("proxies") or not read(bundle / "desktop.json").get("rules"):
            raise Error("empty subscription rejected")
    return m


def configuration(c, token, manifest=None):
    root = Path(c["root"])
    address(c["domain"])
    address(c.get("listen", "0.0.0.0"))
    port(c["port"])
    if not root.is_absolute() or root == Path("/"):
        raise Error("publication root must be a dedicated absolute directory")
    if urllib.parse.urlsplit(origin_url(c["base_url"])).hostname != c["domain"]:
        raise Error("publication origin and certificate domain differ")
    u = urllib.parse.urlsplit(c["base_url"])
    if (u.port or 443) != c["port"] and not c.get("reverse_proxy", False):
        raise Error("publication origin and port differ; reverse_proxy must be explicit")
    lines = [
        f'pid {quote(root / "nginx.pid")};',
        f'error_log {quote(root / "error.log")} warn;',
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
    manifest = manifest or {"artifacts": {f: "" for f in FILES if f != "manifest.json"}}
    for public_path, f in endpoints(manifest, token).items():
        mime = "text/plain" if f.endswith(".txt") else "application/json"
        lines.append(
            f'location = {quote(public_path)} {{ default_type {mime}; limit_except GET {{ deny all; }} alias {quote(root / "current" / f)}; }}'
        )
    if manifest.get("access_mode") == "public" and "clash" in manifest.get("selected_formats", []):
        lines.append(
            f'location ~ "^/rules/([a-f0-9]{{20}})/(domains|cidrs)\\.txt$" {{ alias {quote(root / "rule-releases")[:-1]}/$1/$2.txt"; }}'
        )
    lines += ["location / { return 404; }", "} }"]
    return "\n".join(lines) + "\n"


def endpoints(m, token):
    files = [*m["artifacts"], "manifest.json"]
    if m.get("access_mode") != "public":
        return {"/" + token + "/" + f: f for f in files}
    name = m["name"]
    from .config import name as check_name

    check_name(name)
    paths = {
        "manifest.json": "/version.json",
        "desktop.json": f"/clash/{name}.yaml",
        "nodes.json": f"/clash/providers/{name}.yaml",
        "v2ray.txt": f"/v2ray/{name}.txt",
    }
    return {path: f for f, path in paths.items() if f in files}


def health(c, m, token):
    paths = endpoints(m, token)
    if m.get("access_mode") == "public" and "clash" in m.get("selected_formats", []):
        paths.update(
            {
                f'/rules/{m["rule_version"]}/{kind}.txt': f"rules/{kind}.txt"
                for kind in ("domains", "cidrs")
            }
        )
    for path, f in paths.items():
        if f == "manifest.json":
            continue
        args = [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--connect-timeout",
            "3",
            "--max-time",
            "10",
            "--resolve",
            f'{c["domain"]}:{c["port"]}:127.0.0.1',
        ]
        if c.get("ca_file"):
            args += ["--cacert", c["ca_file"]]
        for attempt in range(5):
            response = run(args + [f'https://{c["domain"]}:{c["port"]}{path}'], check=False)
            if response.returncode == 0 and digest(response.stdout) == m["artifacts"][f]:
                break
            if attempt == 4:
                raise Error("published HTTPS content differs from release")
            time.sleep(0.2)


def recover(c, root, service_name):
    pending = root / "pending.json"
    if not pending.exists():
        return
    snapshot = read(pending)
    if snapshot["target"]:
        repoint(root, snapshot["target"])
    else:
        (root / "current").unlink(missing_ok=True)
    if snapshot["config"] is not None:
        atomic(root / "nginx.conf", snapshot["config"])
    if snapshot["unit"] is not None:
        atomic(SYSTEMD_UNITS / service_name, snapshot["unit"], 0o644)
    run(["systemctl", "daemon-reload"])
    if snapshot["active"]:
        run(["systemctl", "reload-or-restart", service_name])
    else:
        run(["systemctl", "stop", service_name])
    run(["systemctl", "enable" if snapshot["enabled"] else "disable", service_name])
    if snapshot["unit"] is None:
        (SYSTEMD_UNITS / service_name).unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])
    if snapshot["config"] is None:
        (root / "nginx.conf").unlink(missing_ok=True)
    atomic(root / "owner.json", snapshot["owner"])
    pending.unlink()


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


def publish(c, bundle, access_file, allow_candidates=False, *, expected_revision=None):
    if os.geteuid() != 0:
        raise Error("static publication requires root on the web host")
    root = Path(c["root"])
    if root.exists() and any(root.iterdir()) and not (root / "owner.json").exists():
        raise Error("publication root is not owned by this project")
    bundle = Path(bundle)
    m = validate_bundle(bundle)
    token = "" if m.get("access_mode") == "public" else access(access_file)
    config = configuration(c, token, m)
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
        service_name = "vrk-subscription-" + digest(str(root))[:10] + ".service"
        recover(c, root, service_name)
        if not running(root):
            with socket.socket() as s:
                try:
                    s.bind((c.get("listen", "0.0.0.0"), c["port"]))
                except OSError:
                    raise Error("publication port occupied; existing listener untouched") from None
        state = read(root / "owner.json") if (root / "owner.json").exists() else {}
        if expected_revision is not None and state.get("revision") != expected_revision:
            raise Error("subscription changed before rollback; refusing stale rollback")
        if state and state["config"] != c:
            raise Error("web listener settings changed; reconcile explicitly before publication")
        if not state:
            atomic(root / "owner.json", {"config": c, "revision": None, "previous": None})
        if not (root / "error.log").exists():
            atomic(root / "error.log", "")
        (root / "error.log").chmod(0o600)
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
            files = [*m["artifacts"], "manifest.json"]
            for f in files:
                dest = temp / f
                dest.parent.mkdir(mode=0o750, exist_ok=True)
                shutil.copyfile(bundle / f, dest)
            # Rollback keeps the current access token; old tokens must not be re-enabled.
            for f in ("desktop.json", "openwrt-example.json"):
                if f not in files:
                    continue
                document = read(temp / f)

                def urls(v):
                    if isinstance(v, dict):
                        return {k: urls(x) for k, x in v.items()}
                    if isinstance(v, list):
                        return [urls(x) for x in v]
                    if (
                        token
                        and isinstance(v, str)
                        and v.startswith(c["base_url"].rstrip("/") + "/")
                    ):
                        u = urllib.parse.urlsplit(v)
                        parts = u.path.strip("/").split("/")
                        if len(parts) >= 2 and len(parts[0]) == 43:
                            return (
                                c["base_url"].rstrip("/") + "/" + token + "/" + "/".join(parts[1:])
                            )
                    return v

                atomic(temp / f, urls(document))
            m["artifacts"] = {
                f: digest((temp / f).read_bytes()) for f in files if f != "manifest.json"
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
            for f in files:
                run(["runuser", "-u", user, "--", "test", "-r", target / f])
            atomic(root / "candidate.conf", config)
            test = run(
                [nginx, "-t", "-p", str(root) + "/", "-c", root / "candidate.conf"], check=False
            )
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
            snapshot = {
                "target": old_target,
                "config": old_config,
                "owner": state or {"config": c, "revision": None, "previous": None},
                "unit": service_file.read_text() if service_file.exists() else None,
                "active": run(["systemctl", "is-active", service_name], check=False).returncode
                == 0,
                "enabled": run(["systemctl", "is-enabled", service_name], check=False).returncode
                == 0,
            }
            if m.get("access_mode") == "public" and "clash" in m["selected_formats"]:
                rule_dir = root / "rule-releases" / m["rule_version"]
                rule_dir.mkdir(parents=True, exist_ok=True)
                for part in (rule_dir.parent, rule_dir):
                    os.chown(part, 0, gid)
                    part.chmod(0o750)
                for kind in ("domains", "cidrs"):
                    source = target / "rules" / (kind + ".txt")
                    dest = rule_dir / source.name
                    if dest.exists() and dest.read_bytes() != source.read_bytes():
                        raise Error("immutable rule version collision")
                    shutil.copyfile(source, dest)
                    os.chown(dest, 0, gid)
                    dest.chmod(0o640)
            atomic(
                root / "logrotate.conf",
                quote(root / "error.log") + " {\n"
                " size 5M\n rotate 7\n missingok\n notifempty\n compress\n delaycompress\n"
                " create 0600 root root\n postrotate\n"
                + "  /bin/systemctl reload "
                + service_name
                + " >/dev/null 2>&1 || true\n"
                " endscript\n}\n",
            )
            rotate_link = LOGROTATE / service_name.removesuffix(".service")
            if not LOGROTATE.is_dir():
                raise Error("install distribution logrotate before publication")
            if rotate_link.exists() or rotate_link.is_symlink():
                if (
                    not rotate_link.is_symlink()
                    or rotate_link.resolve() != (root / "logrotate.conf").resolve()
                ):
                    raise Error("logrotate entry belongs to another manager")
            else:
                rotate_link.symlink_to(root / "logrotate.conf")
            atomic(root / "pending.json", snapshot)
            repoint(root, "releases/" + target.name)
            atomic(root / "nginx.conf", config)
            atomic(service_file, service, 0o644)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", service_name])
            active = run(["systemctl", "is-active", service_name], check=False).returncode == 0
            run(["systemctl", "reload" if active else "start", service_name])
            health(c, m, token)
            previous = (
                state.get("previous") if state.get("revision") == m["revision"] else old_target
            )
            atomic(
                root / "owner.json", {"config": c, "revision": m["revision"], "previous": previous}
            )
            (root / "pending.json").unlink()
        except BaseException:
            if (root / "pending.json").exists():
                recover(c, root, service_name)
            raise
        finally:
            if temp.exists():
                shutil.rmtree(temp)
    return {"revision": m["revision"], "published": True, "candidate_only": m["candidate_only"]}


def rollback(c, access_file, allow_candidates=False, revision=None):
    state = read(Path(c["root"]) / "owner.json")
    if revision is not None and not re.fullmatch("[a-f0-9]{20}", revision):
        raise Error("invalid release revision")
    previous = "releases/" + revision if revision else state.get("previous")
    if not previous or not previous.startswith("releases/") or ".." in previous:
        raise Error("no previous subscription release")
    return publish(
        c,
        Path(c["root"]) / previous,
        access_file,
        allow_candidates,
        expected_revision=state["revision"],
    )


def prune(c, keep=5, older_than_days=30, execute=False):
    if keep < 2 or older_than_days < 1:
        raise Error("retain at least two releases and one day")
    root = Path(c["root"])
    with (root / "publish.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (root / "pending.json").exists():
            raise Error("recover pending publication before pruning")
        state = read(root / "owner.json")
        protected = {state["revision"], Path(state.get("previous") or "").name}
        releases = sorted(
            (
                p
                for p in (root / "releases").iterdir()
                if p.is_dir() and not p.is_symlink() and re.fullmatch("[a-f0-9]{20}", p.name)
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        protected.update(p.name for p in releases[:keep])
        cutoff = time.time() - older_than_days * 86400
        removed = [
            p.name for p in releases if p.name not in protected and p.stat().st_mtime < cutoff
        ]
        for revision in removed:
            if execute:
                shutil.rmtree(root / "releases" / revision)
        return {"execute": execute, "releases": removed, "protected": sorted(protected)}


def status(c):
    root = Path(c["root"])
    owner = read(root / "owner.json")
    certificate = run(
        ["openssl", "x509", "-in", c["certificate"], "-noout", "-enddate"]
    ).stdout.strip()
    renew = run(
        ["openssl", "x509", "-in", c["certificate"], "-noout", "-checkend", str(90 * 86400)],
        check=False,
    )
    return {
        "revision": owner["revision"],
        "previous": owner["previous"],
        "running": running(root),
        "pending": (root / "pending.json").exists(),
        "certificate": certificate,
        "certificate_expires_within_90_days": renew.returncode != 0,
    }
