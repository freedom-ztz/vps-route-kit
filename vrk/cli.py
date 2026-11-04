import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
from . import __version__
from .config import sample, validate
from .core import SOURCE, LOCK
from .util import Error, atomic, encode, read, redact, run


def parser():
    p = argparse.ArgumentParser(prog="vrk", description="VPS Route Kit：三协议部署、中转与分流")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    for command in [
        "menu",
        "init",
        "validate",
        "plan",
        "apply",
        "status",
        "logs",
        "export",
        "doctor",
        "benchmark",
        "verify",
        "backup",
        "rollback",
        "upgrade",
        "uninstall",
    ]:
        s = sub.add_parser(command)
        if command not in ("init", "validate", "benchmark", "verify"):
            s.add_argument("--host")
        s.add_argument("--jump")
        if command in ["init", "validate", "plan", "apply", "upgrade", "menu"]:
            s.add_argument("--config", default="vrk.json")
        if command == "plan":
            s.add_argument("--lock")
        if command in ["apply", "upgrade"]:
            s.add_argument("--secrets")
            s.add_argument("--lock")
        if command == "init":
            s.add_argument("--output", default="vrk.json")
        if command == "export":
            s.add_argument(
                "--format", choices=["mihomo", "xray", "hysteria", "uri", "nodes"], default="mihomo"
            )
            s.add_argument("--output", required=True)
            s.add_argument("--listener")
            s.add_argument("--name-prefix", default="")
            s.add_argument("--dialer-proxy")
            s.add_argument("--address")
            s.add_argument("--port-map", default="{}")
        if command == "logs":
            s.add_argument("--lines", type=int, default=100)
        if command == "rollback":
            s.add_argument("--snapshot")
        if command == "upgrade":
            s.add_argument("--component", choices=["xray", "hysteria", "realm"], required=True)
            s.add_argument("--to", required=True)
        if command == "verify":
            s.add_argument("--cases", required=True)
            s.add_argument("--output", required=True)
        if command == "benchmark":
            s.add_argument("--timeout", type=int, default=90)
            s.add_argument("--cpu-host")
            s.add_argument("--proxy", required=True)
            s.add_argument("--down-url", required=True)
            s.add_argument("--up-url", required=True)
            s.add_argument("--rounds", type=int, default=3)
            s.add_argument("--output", required=True)
    return p


def menu(a):
    choices = {
        "1": "plan",
        "2": "apply",
        "3": "status",
        "4": "doctor",
        "5": "logs",
        "6": "backup",
        "7": "rollback",
        "8": "export",
        "9": "uninstall",
        "10": "verify",
    }
    while True:
        print(
            "\nVPS Route Kit\n1 查看变更  2 部署配置  3 服务状态  4 诊断\n5 日志  6 备份  7 回滚  8 导出节点  9 卸载服务  10 网络验收  0 退出\n节点、规则和证书设置：编辑 "
            + a.config
            + " 后使用“查看变更”和“部署配置”。"
        )
        choice = input("选择：").strip()
        if choice == "0":
            return
        if choice not in choices:
            continue
        command = choices[choice]
        args = [command]
        if command in ("apply", "plan"):
            args += ["--config", a.config]
        if a.host and command != "verify":
            args += ["--host", a.host]
        if a.jump and command != "verify":
            args += ["--jump", a.jump]
        if command == "verify":
            args += [
                "--cases",
                input("验收清单 JSON：").strip(),
                "--output",
                input("新结果 JSONL 文件：").strip(),
            ]
        if command == "export":
            args += ["--output", input("导出文件：").strip()]
        if command == "uninstall" and input("输入 uninstall 确认移除项目服务：") != "uninstall":
            continue
        main(args)


def main(argv=None):
    os.umask(0o077)
    a = parser().parse_args(argv)
    try:
        if a.command == "menu":
            return menu(a)
        if a.command == "init":
            if Path(a.output).exists():
                raise Error("output exists")
            atomic(a.output, sample())
            print("Created " + a.output)
            return
        if a.command == "validate":
            validate(read(a.config))
            print("Configuration valid")
            return
        if getattr(a, "host", None):
            from .remote import execute

            if a.command == "export":
                # Remote output remains on the private SSH channel, never on the terminal.
                args = [
                    "export",
                    "--format",
                    a.format,
                    "--output",
                    "/dev/stdout",
                    "--port-map",
                    a.port_map,
                    "--name-prefix",
                    a.name_prefix,
                ]
                if a.dialer_proxy:
                    args += ["--dialer-proxy", a.dialer_proxy]
                if a.listener:
                    args += ["--listener", a.listener]
                if a.address:
                    args += ["--address", a.address]
                data = execute(a.host, args, jump=a.jump)
                atomic(a.output, data)
                print("Exported " + a.output)
                return
            args = [a.command]
            if a.command == "logs":
                args += ["--lines", str(a.lines)]
            if a.command == "rollback" and a.snapshot:
                args += ["--snapshot", a.snapshot]
            if a.command == "upgrade":
                args += ["--component", a.component, "--to", a.to]
            print(
                execute(
                    a.host,
                    args,
                    jump=a.jump,
                    config=getattr(a, "config", None),
                    secrets=getattr(a, "secrets", None),
                    lock=getattr(a, "lock", None),
                ),
                end="",
            )
            return
        from . import deploy

        if a.command == "plan":
            c = validate(read(a.config))
            old = deploy.state()
            # Read-only plan never generates credentials or downloads binaries.
            from .config import referenced_nodes

            print(
                encode(
                    {
                        "config_changed": old.get("config") != c,
                        "versions_changed": old.get("versions") != read(a.lock or LOCK),
                        "versions": {"before": old.get("versions"), "after": read(a.lock or LOCK)},
                        "changes": {
                            key: {"before": old.get("config", {}).get(key), "after": c.get(key)}
                            for key in [
                                "address",
                                "listeners",
                                "nodes",
                                "routing",
                                "relays",
                                "manage_firewall",
                            ]
                            if old.get("config", {}).get(key) != c.get(key)
                        },
                        "bindings": c["_bindings"],
                        "remote_nodes": sorted(referenced_nodes(c)),
                        "routing": c["routing"],
                        "relays": c.get("relays", []),
                        "firewall_required": [
                            {"transport": t, "port": p}
                            for t, h, p in c["_bindings"]
                            if h not in ("127.0.0.1", "::1")
                        ],
                        "acme_tcp80": any(
                            l.get("certificate", {}).get("mode") == "acme" for l in c["listeners"]
                        ),
                    }
                )
            )
            return
        if a.command in ("apply", "upgrade"):
            if a.command == "upgrade":
                lock = read(a.lock or LOCK)
                if lock[a.component]["version"] != a.to:
                    raise Error("target version must exist in the reviewed lock file")
            deploy.apply(read(a.config), a.secrets, a.lock)
            return
        if a.command == "backup":
            deploy.backup()
            return
        if a.command == "rollback":
            deploy.rollback(a.snapshot)
            return
        if a.command == "uninstall":
            deploy.uninstall()
            return
        if a.command in ("status", "doctor"):
            s = deploy.state()
            result = {
                "generation": s["generation"],
                "services": deploy.service_state(s["services"]),
            }
            if a.command == "doctor":
                result["bindings"] = s["bindings"]
                result["pending_recovery"] = (deploy.ROOT / "pending.json").exists()
                result["checks"] = {
                    k: run(v, check=False).returncode == 0
                    for k, v in {
                        "nft_available": ["which", "nft"],
                        "dns": ["getent", "hosts", "example.com"],
                    }.items()
                }
                result["firewall_policy"] = (
                    "Only scoped nft rules are supported; use docs/deployment.md. No existing firewall is flushed."
                )
            print(encode(result))
            return
        if a.command == "logs":
            s = deploy.state()
            args = ["journalctl", "--no-pager", "-n", str(max(1, min(a.lines, 10000)))]
            for n in s["services"]:
                args += ["-u", n]
            if not s["services"]:
                print("No managed services")
                return
            print(redact(run(args).stdout, read(deploy.ROOT / "secrets.json")))
            return
        if a.command == "export":
            from .export import export

            s = deploy.state()
            if not s.get("generation"):
                raise Error("no deployed generation")
            result = export(
                s["config"],
                read(deploy.ROOT / "secrets.json"),
                a.format,
                a.address,
                json.loads(a.port_map),
                a.listener,
                a.name_prefix,
                a.dialer_proxy,
            )
            data = result if isinstance(result, str) else encode(result)
            if a.output == "/dev/stdout":
                sys.stdout.write(data)
            else:
                atomic(a.output, data)
                print("Exported " + a.output)
            return
        if a.command == "verify":
            from .verification import verify

            result = verify(read(a.cases), a.output)
            print(encode(result))
            return 0 if result["all_declared_passed"] else 1
        if a.command == "benchmark":
            from .diagnostics import benchmark

            atomic(
                a.output,
                benchmark(
                    a.proxy,
                    a.down_url,
                    a.up_url,
                    a.rounds,
                    cpu_host=a.cpu_host,
                    jump=a.jump,
                    request_timeout=a.timeout,
                ),
            )
            print("Saved " + a.output)
    except (Error, ValueError, KeyError, OSError) as e:
        print("vrk: " + str(e), file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("vrk: SSH operation timed out; inspect status before retry", file=sys.stderr)
        return 1
    return 0
