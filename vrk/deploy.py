import contextlib
import fcntl
import grp
import pwd
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tarfile
import time
from . import __version__
from .config import referenced_nodes, validate
from .core import SOURCE, LOCK, binary, credentials
from .render import render
from .util import Error, atomic, digest, encode, read, run

ROOT = Path("/var/lib/vrk")
OPT = Path("/opt/vrk")
UNITS = Path("/etc/systemd/system")


def systemctl(*args, check=True):
    return run(["systemctl", *args], check=check)


def environment():
    if os.geteuid() != 0:
        raise Error("apply requires root")
    release = Path("/etc/os-release").read_text()
    if not (
        ("ID=debian" in release and 'VERSION_ID="12"' in release)
        or ("ID=ubuntu" in release and 'VERSION_ID="24.04"' in release)
    ):
        raise Error("supported OS: Debian 12 / Ubuntu 24.04")
    if not Path("/run/systemd/system").exists():
        raise Error("systemd is not running")
    for command in ("ss", "systemctl", "runuser"):
        if not shutil.which(command):
            raise Error(f"missing system dependency: {command}")


@contextlib.contextmanager
def locked():
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
    with (ROOT / "deploy.lock").open("w") as f:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def state():
    return (
        read(ROOT / "state.json")
        if (ROOT / "state.json").exists()
        else {"services": {}, "bindings": [], "generation": None}
    )


def service_state(names):
    return {
        n: {
            "active": systemctl("is-active", n, check=False).stdout.strip() == "active",
            "enabled": systemctl("is-enabled", n, check=False).stdout.strip() == "enabled",
        }
        for n in names
    }


def socket_rows():
    rows = []
    for line in run(["ss", "-H", "-lntup"]).stdout.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        endpoint = cols[4]
        try:
            h, p = endpoint.rsplit(":", 1)
            p = int(p)
        except ValueError:
            continue
        rows.append((cols[0], h.strip("[]"), p, {int(x) for x in re.findall(r"pid=(\d+)", line)}))
    return rows


def owned_pids(old):
    pids = set()
    for n in old["services"]:
        p = systemctl("show", n, "-p", "MainPID", "--value", check=False).stdout.strip()
        if p.isdigit() and int(p) > 0:
            pids.add(int(p))
    return pids


def preflight(c, old):
    pids = owned_pids(old)
    for t, h, p in c["_bindings"]:
        for tt, hh, pp, owners in socket_rows():
            if tt == t and pp == p and (hh in (h, "*", "0.0.0.0", "::") or h in ("0.0.0.0", "::")):
                if not owners or not owners <= pids:
                    raise Error(f"port conflict: {t}/{p}; foreign service remains untouched")
    for l in c["listeners"]:
        if l["protocol"] != "hysteria2":
            continue
        cert = l["certificate"]
        if cert["mode"] == "acme":
            if not any((ROOT / "acme" / l["id"]).rglob("*.crt")):
                if any(p == 80 and t == "tcp" for t, h, p, owners in socket_rows()):
                    raise Error("ACME requires free TCP 80; use certificate files instead")
                answers = {
                    a[4][0] for a in socket.getaddrinfo(l["server_name"], None, socket.AF_INET)
                }
                expected = {a[4][0] for a in socket.getaddrinfo(c["address"], None, socket.AF_INET)}
                if not expected & answers:
                    raise Error("ACME A record does not point to this host")
        else:
            for key in ("cert", "key"):
                if not Path(cert[key]).is_file():
                    raise Error("certificate file missing")
                if run(
                    ["runuser", "-u", "vrk", "--", "test", "-r", cert[key]], check=False
                ).returncode:
                    raise Error("certificate must be readable by vrk service user")


def unit(component, binary_path, args, dependencies=()):
    command = " ".join(
        '"' + str(a).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'
        for a in [binary_path, *args]
    )
    dep = " ".join(n + ".service" for n in dependencies)
    return f"""# Managed by VPS Route Kit
[Unit]
Description=VPS Route Kit {component}
After=network-online.target {dep}
Wants=network-online.target
[Service]
User=vrk
Group=vrk
ExecStart={command}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
UMask=0027
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
"""


def install_user():
    if not run(["id", "-u", "vrk"], check=False).returncode:
        account = pwd.getpwnam("vrk")
        if account.pw_uid >= 1000 or account.pw_shell not in (
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/bin/false",
        ):
            raise Error("existing vrk account is not a dedicated service account")
    else:
        run(["useradd", "--system", "--home-dir", str(ROOT), "--shell", "/usr/sbin/nologin", "vrk"])
    gid = grp.getgrnam("vrk").gr_gid
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(ROOT, 0, gid)
    ROOT.chmod(0o750)
    for path in [ROOT / "acme"]:
        path.mkdir(exist_ok=True)
        shutil.chown(path, user="vrk", group="vrk")
        path.chmod(0o700)
    return gid


def point(generation):
    tmp = ROOT / "current.new"
    tmp.unlink(missing_ok=True)
    tmp.symlink_to(ROOT / "generations" / generation)
    os.replace(tmp, ROOT / "current")


def restore(snapshot):
    old = snapshot["state"]
    names = set(state()["services"]) | set(snapshot.get("candidate_services", {}))
    for n in names:
        systemctl("stop", n, check=False)
    for n in names | set(old["services"]):
        path = UNITS / (n + ".service")
        if n in old["services"]:
            atomic(path, old["services"][n], 0o644)
        else:
            systemctl("disable", n, check=False)
            path.unlink(missing_ok=True)
    if old["generation"]:
        point(old["generation"])
    else:
        (ROOT / "current").unlink(missing_ok=True)
    systemctl("daemon-reload")
    for n, ss in snapshot["service_state"].items():
        systemctl("enable" if ss["enabled"] else "disable", n, check=False)
        if ss["active"]:
            systemctl("start", n)
    atomic(ROOT / "state.json", old)
    if "secrets" in snapshot:
        if snapshot["secrets"] is None:
            (ROOT / "secrets.json").unlink(missing_ok=True)
        else:
            atomic(ROOT / "secrets.json", snapshot["secrets"])
    (ROOT / "pending.json").unlink(missing_ok=True)


def wait_healthy(current, timeout=65):
    deadline = time.monotonic() + timeout
    while True:
        active = all(
            systemctl("is-active", n, check=False).stdout.strip() == "active"
            for n in current["services"]
        )
        rows = socket_rows()
        pids = owned_pids(current)
        ready = all(
            any(
                t == tt
                and p == pp
                and (hh in (h, "*") or h == "0.0.0.0" and hh == "0.0.0.0")
                and bool(owners & pids)
                for tt, hh, pp, owners in rows
            )
            for t, h, p in current["bindings"]
        )
        if active and ready:
            break
        if time.monotonic() > deadline:
            raise Error("service/listener health check timed out")
        time.sleep(1)
    time.sleep(2)
    if not all(
        systemctl("is-active", n, check=False).stdout.strip() == "active"
        for n in current["services"]
    ):
        raise Error("service exited after startup")


def unit_runtime(content):
    """Compare generated runtime directives without tool-version comments."""
    return "\n".join(
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def impact(c, old, lock):
    """Conservative service impact without generating keys or downloading cores."""
    previous = old.get("config", {})

    def services(cfg):
        if not cfg:
            return {}
        secrets = {}
        for item in list(cfg.get("listeners", [])) + list(cfg.get("nodes", {}).values()):
            secrets[item["secret"]] = {
                "uuid": "stable",
                "private_key": "stable",
                "public_key": "stable",
                "short_id": "stable",
                "password": "stable",
            }
        files, args = render(cfg, secrets, str(ROOT))
        result = {}
        for n, (component, command) in args.items():
            names = [
                Path(a).name for a in command if str(a).startswith(str(ROOT / "current") + "/")
            ]
            result[n] = (component, [files.get(f) for f in names])
        if cfg.get("manage_firewall"):
            from .firewall import rules

            result["vrk-firewall"] = ("nft", [rules(cfg)])
        return result

    before, after = services(previous), services(c)
    changes = []
    for n in sorted(set(before) | set(after)):
        action = "add" if n not in before else "remove" if n not in after else "unchanged"
        if action == "unchanged":
            component = after[n][0]
            if before[n] != after[n] or old.get("versions", {}).get(component) != lock.get(
                component
            ):
                action = "restart"
        listeners = [
            l["id"]
            for l in (c if n in after else previous).get("listeners", [])
            if (n == "vrk-xray" and l["protocol"] != "hysteria2") or n == "vrk-hy-" + l["id"]
        ]
        if n == "vrk-xray":
            from .render import bridge_required

            if bridge_required(c):
                listeners += [l["id"] for l in c["listeners"] if l["protocol"] == "hysteria2"]
        changes.append(
            {"service": n, "action": action, "affected_listeners": sorted(set(listeners))}
        )
    return {
        "services": changes,
        "note": "Shared Xray listeners are affected together; imported credential changes require apply-time inspection.",
    }


def acceptance_decision(before, after):
    failed_targets = {
        k.rsplit("/", 1)[1]
        for k, v in after["cases"].items()
        if v["failures"] and before["cases"].get(k, {}).get("failures") == 0
    }
    return {
        "before_passed": before["all_declared_passed"],
        "after_passed": after["all_declared_passed"],
        "decision": (
            "rollback"
            if len(failed_targets) >= 2
            else "passed" if after["all_declared_passed"] else "undetermined_external_failure"
        ),
    }


def apply(c, secrets_file=None, lock_file=None, verify_cases=None, verify_output=None):
    environment()
    baseline = None
    if verify_cases:
        from .verification import verify

        if not verify_output or len(verify_cases.get("targets", [])) < 2:
            raise Error("acceptance requires a new output directory and at least two HTTPS targets")
        verify_output = Path(verify_output)
        verify_output.mkdir(mode=0o700, parents=True, exist_ok=False)
        baseline = verify(verify_cases, verify_output / "before.jsonl")
    with locked():
        if (ROOT / "pending.json").exists():
            restore(read(ROOT / "pending.json"))
        c = validate(c)
        old = state()
        gid = install_user()
        preflight(c, old)
        if c.get("manage_firewall"):
            from .firewall import check

            check()
        lock = read(lock_file or LOCK)
        required = (
            {"xray"}
            if any(l["protocol"] != "hysteria2" for l in c["listeners"])
            or referenced_nodes(c)
            or c["routing"].get("rules")
            else set()
        )
        if any(l["protocol"] == "hysteria2" for l in c["listeners"]) or any(
            c["nodes"][n]["protocol"] == "hysteria2" for n in referenced_nodes(c)
        ):
            required.add("hysteria")
        if c.get("relays"):
            required.add("realm")
        binaries = {n: binary(n, lock, OPT) for n in required}
        s = read(ROOT / "secrets.json") if (ROOT / "secrets.json").exists() else {}
        if secrets_file:
            s.update(read(secrets_file))
        s = credentials(c, s, binaries.get("xray"))
        files, service_args = render(c, s, str(ROOT))
        # The bridge itself requires Xray even when no VLESS listener is present.
        for comp, args in service_args.values():
            if comp not in binaries:
                binaries[comp] = binary(comp, lock, OPT)
        services = {
            n: unit(
                comp,
                binaries[comp],
                args,
                (
                    [k for k in service_args if k.startswith("vrk-hy-client-")]
                    if n == "vrk-xray"
                    else (
                        ["vrk-xray"]
                        if n.startswith("vrk-hy-")
                        and not n.startswith("vrk-hy-client-")
                        and "vrk-xray" in service_args
                        else []
                    )
                ),
            )
            for n, (comp, args) in service_args.items()
        }
        if c.get("manage_firewall"):
            from .firewall import rules, service

            files["firewall.nft"] = rules(c)
            services["vrk-firewall"] = service(str(ROOT))
        for n in services:
            path = UNITS / (n + ".service")
            if path.exists() and n not in old["services"]:
                raise Error("unmanaged service name conflict: " + n)
            if n in old["services"] and path.exists() and path.read_text() != old["services"][n]:
                raise Error("managed unit was edited externally; reconcile before apply")
        generation = digest(
            encode({"config": c, "files": files, "services": services, "lock": lock})
        )[:20]
        if (
            old.get("generation") == generation
            and all((UNITS / (n + ".service")).exists() for n in services)
            and all(
                (ROOT / "current" / path).exists() and (ROOT / "current" / path).read_text() == data
                for path, data in files.items()
            )
        ):
            for n in services:
                systemctl("enable", n)
                if systemctl("is-active", n, check=False).stdout.strip() != "active":
                    systemctl("start", n)
            wait_healthy(old)
            if verify_cases:
                after = verify(verify_cases, verify_output / "after.jsonl")
                verdict = acceptance_decision(baseline, after)
                if verdict["decision"] == "rollback":
                    verdict["decision"] = "undetermined_external_failure"
                atomic(verify_output / "decision.json", verdict)
            print(encode({"changed": False, "generation": generation}))
            return old
        generations = ROOT / "generations"
        generations.mkdir(exist_ok=True)
        os.chown(generations, 0, gid)
        generations.chmod(0o750)
        target = generations / generation
        target.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chown(target, 0, gid)
        target.chmod(0o750)
        for path, data in files.items():
            dest = target / path
            atomic(dest, data, 0o640)
            os.chown(dest, 0, gid)
            if dest.parent != target:
                os.chown(dest.parent, 0, gid)
                dest.parent.chmod(0o750)
        atomic(target / "config.json", c)
        atomic(target / "versions.lock.json", lock)
        atomic(target / "secrets.json", s)
        validation = {}
        if "firewall.nft" in files:
            run(["nft", "-c", "-f", target / "firewall.nft"])
        if "xray.json" in files:
            p = run(
                [
                    "runuser",
                    "-u",
                    "vrk",
                    "--",
                    binaries["xray"],
                    "run",
                    "-test",
                    "-config",
                    target / "xray.json",
                ],
                check=False,
            )
            atomic(target / "validation.log", p.stdout + p.stderr)
            if p.returncode:
                raise Error("Xray configuration validation failed; previous generation unchanged")
            validation["xray"] = "passed"
        # Hysteria/Realm have no stable parse-only command. Validate schema here;
        # require listener readiness during the protected activation below.
        snapshot = {
            "secrets": read(ROOT / "secrets.json") if (ROOT / "secrets.json").exists() else None,
            "state": old,
            "service_state": service_state(old["services"]),
            "candidate_services": services,
        }
        backup = ROOT / "backups" / f"{time.time_ns()}.json"
        atomic(backup, snapshot)
        atomic(ROOT / "pending.json", snapshot)
        try:
            changed = set(services) - set(old["services"])
            for n in set(services) & set(old["services"]):
                comp, args = service_args.get(n, ("nft", []))
                relevant = [
                    Path(arg).name
                    for arg in args
                    if str(arg).startswith(str(ROOT / "current") + "/")
                ]
                if n == "vrk-firewall":
                    relevant = ["firewall.nft"]
                if comp == "hysteria" and "server" in args:
                    relevant += ["www/index.html"]
                old_dir = ROOT / "generations" / str(old.get("generation"))
                if unit_runtime(services[n]) != unit_runtime(old["services"][n]) or any(
                    not (old_dir / f).exists() or (old_dir / f).read_text() != files.get(f, "")
                    for f in relevant
                ):
                    changed.add(n)
            for n in old["services"]:
                if n in changed or n not in services:
                    systemctl("stop", n, check=False)
            point(generation)
            for n, content in services.items():
                atomic(UNITS / (n + ".service"), content, 0o644)
            for n in set(old["services"]) - set(services):
                systemctl("disable", n, check=False)
                (UNITS / (n + ".service")).unlink(missing_ok=True)
            systemctl("daemon-reload")
            ordered = sorted(
                services,
                key=lambda n: (
                    (
                        -1
                        if n == "vrk-firewall"
                        else 0 if n.startswith("vrk-hy-client-") else 1 if n == "vrk-xray" else 2
                    ),
                    n,
                ),
            )
            for n in ordered:
                systemctl("enable", n)
                systemctl("start", n)
            new = {
                "generation": generation,
                "services": services,
                "bindings": c["_bindings"],
                "config": c,
                "versions": lock,
                "previous_backup": str(backup),
            }
            atomic(ROOT / "state.json", new)
            wait_healthy(new)
            if verify_cases:
                after = verify(verify_cases, verify_output / "after.jsonl")
                verdict = acceptance_decision(baseline, after)
                atomic(verify_output / "decision.json", verdict)
                if verdict["decision"] == "rollback":
                    raise Error(
                        "multiple previously healthy targets regressed; restoring previous generation"
                    )
                validation["network_acceptance"] = verdict["decision"]
            atomic(ROOT / "secrets.json", s)
            (ROOT / "pending.json").unlink()
        except BaseException:
            restore(snapshot)
            if verify_cases:
                from .verification import verify

                verify(verify_cases, verify_output / "restored.jsonl")
            raise
        print(
            encode(
                {
                    "changed": True,
                    "generation": generation,
                    "backup": str(backup),
                    "validation": validation,
                }
            )
        )
        return new


def backup():
    with locked():
        if (ROOT / "pending.json").exists():
            raise Error("pending deployment: recover with apply before backup")
        directory = ROOT / "archives"
        directory.mkdir(exist_ok=True, mode=0o700)
        dest = directory / (str(time.time_ns()) + ".tar.gz")
        with tarfile.open(dest, "w:gz") as archive:
            for p in [
                ROOT / "state.json",
                ROOT / "secrets.json",
                ROOT / "generations",
                ROOT / "acme",
                ROOT / "backups",
            ]:
                if p.exists():
                    archive.add(p, arcname=p.relative_to(ROOT))
        dest.chmod(0o600)
        print(dest)
        return dest


def rollback(path=None):
    environment()
    with locked():
        old = state()
        p = Path(path or old.get("previous_backup", ""))
        if not p.is_file() or p.parent != ROOT / "backups":
            raise Error("select a deployment snapshot from /var/lib/vrk/backups")
        restore(read(p))
        print(encode({"rolled_back": str(p)}))


def uninstall():
    environment()
    with locked():
        if (ROOT / "pending.json").exists():
            restore(read(ROOT / "pending.json"))
        old = state()
        for n in old["services"]:
            path = UNITS / (n + ".service")
            if path.exists() and path.read_text() != old["services"][n]:
                raise Error("unit edited externally; refusing uninstall")
        for n in old["services"]:
            systemctl("disable", "--now", n)
            (UNITS / (n + ".service")).unlink(missing_ok=True)
        systemctl("daemon-reload")
        (ROOT / "current").unlink(missing_ok=True)
        atomic(ROOT / "state.json", {"services": {}, "bindings": [], "generation": None})
        print("Services removed; secrets, certificates, binaries and backups retained.")
