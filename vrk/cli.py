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
            s.add_argument("--verify-cases")
            s.add_argument("--verify-output")
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
            s.add_argument("--expected-generation")
            s.add_argument("--snapshot")
        if command == "upgrade":
            s.add_argument("--component", choices=["xray", "hysteria", "realm"], required=True)
            s.add_argument("--to", required=True)
        if command == "verify":
            s.add_argument("--cases", required=True)
            s.add_argument("--output", required=True)
        if command == "benchmark":
            s.add_argument("--connect-ip")
            s.add_argument("--timeout", type=int, default=90)
            s.add_argument("--cpu-host")
            s.add_argument("--proxy", required=True)
            s.add_argument("--down-url", required=True)
            s.add_argument("--up-url", required=True)
            s.add_argument("--rounds", type=int, default=3)
            s.add_argument("--output", required=True)
    cat = sub.add_parser("catalog")
    cat.add_argument("action", choices=["validate", "plan"])
    cat.add_argument("--catalog", required=True)
    cat.add_argument("--previous")
    subscription = sub.add_parser("subscription")
    subscription.add_argument(
        "action", choices=["build", "publish", "rollback", "token", "prune", "status"]
    )
    subscription.add_argument("--host")
    subscription.add_argument("--jump")
    subscription.add_argument("--catalog")
    subscription.add_argument("--output")
    subscription.add_argument("--base-url")
    subscription.add_argument("--access-file")
    subscription.add_argument("--name", default="builder")
    subscription.add_argument("--formats", default="clash,v2ray")
    subscription.add_argument("--access-mode", choices=["public", "token"], default="token")
    subscription.add_argument("--revision")
    subscription.add_argument("--execute", action="store_true")
    subscription.add_argument("--keep", type=int, default=5)
    subscription.add_argument("--older-than-days", type=int, default=30)
    subscription.add_argument("--mihomo")
    subscription.add_argument("--include-candidates", action="store_true")
    subscription.add_argument("--publish-config")
    subscription.add_argument("--bundle")
    subscription.add_argument("--allow-candidates", action="store_true")
    subscription.add_argument("--rotate", action="store_true")
    diagnose = sub.add_parser("diagnose")
    diagnose.add_argument("--catalog", required=True)
    diagnose.add_argument("--cases", required=True)
    diagnose.add_argument("--output", required=True)
    audit = sub.add_parser("audit")
    audit.add_argument("--catalog", required=True)
    audit.add_argument("--cases", required=True)
    audit.add_argument("--output", required=True)
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
        "11": "catalog",
        "12": "subscription",
        "13": "diagnose",
    }
    while True:
        print(
            "\nVPS Route Kit\n1 查看变更  2 部署配置  3 服务状态  4 诊断\n5 日志  6 备份  7 回滚  8 导出节点  9 卸载服务  10 网络验收\n11 线路目录  12 订阅管理  13 分段诊断  0 退出\n节点、规则和证书设置：编辑 "
            + a.config
            + " 后使用“查看变更”和“部署配置”。"
        )
        choice = input("选择：").strip()
        if choice == "0":
            return
        if choice not in choices:
            continue
        command = choices[choice]
        if command == "catalog":
            main([command, "plan", "--catalog", input("私有线路目录 JSON：").strip()])
            continue
        if command == "diagnose":
            main(
                [
                    command,
                    "--catalog",
                    input("私有线路目录 JSON：").strip(),
                    "--cases",
                    input("诊断清单 JSON：").strip(),
                    "--output",
                    input("新结果 JSON：").strip(),
                ]
            )
            continue
        if command == "subscription":
            action = input("操作 build / publish / rollback / token / status / prune：").strip()
            args = [command, action]
            if action in ("build", "publish", "rollback", "token"):
                access_file = input("私有令牌文件（公开模式留空）：").strip()
                if access_file:
                    args += ["--access-file", access_file]
            if action == "build":
                args += [
                    "--access-mode",
                    input("访问方式 public / token [token]：").strip() or "token",
                    "--formats",
                    input("格式 clash / v2ray / clash,v2ray [clash,v2ray]：").strip()
                    or "clash,v2ray",
                    "--name",
                    input("订阅名称 [builder]：").strip() or "builder",
                ]
                for flag, prompt in [
                    ("--catalog", "私有线路目录："),
                    ("--output", "新构建目录："),
                    ("--base-url", "HTTPS 源站："),
                    ("--mihomo", "Mihomo 可执行文件："),
                ]:
                    args += [flag, input(prompt).strip()]
            elif action in ("publish", "rollback", "status", "prune"):
                args += ["--publish-config", input("发布配置 JSON：").strip()]
                if action == "publish":
                    args += ["--bundle", input("构建目录：").strip()]
                if a.host:
                    args += ["--host", a.host]
                    if a.jump:
                        args += ["--jump", a.jump]
            elif action != "token":
                print("未知订阅操作")
                continue
            main(args)
            continue
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
        if a.command == "catalog":
            from .catalog import report

            print(
                encode(
                    report(
                        read(a.catalog),
                        Path(a.catalog).parent,
                        read(a.previous) if a.previous else None,
                    )
                )
            )
            return
        if a.command == "diagnose":
            from .route_diagnostics import diagnose

            result = diagnose(read(a.catalog), read(a.cases), a.output)
            print(encode(result))
            return 0 if result["all_passed"] else 1
        if a.command == "audit":
            from .audit import audit

            result = audit(read(a.catalog), read(a.cases), a.output)
            print(
                encode(
                    {
                        "completed": result["completed"],
                        "routes": {
                            key: {
                                "qualified": row.get("qualified", False),
                                "attribution": row["attribution"],
                            }
                            for key, row in result["routes"].items()
                        },
                    }
                )
            )
            return (
                0
                if result["completed"] and all(r["qualified"] for r in result["routes"].values())
                else 1
            )
        if a.command == "subscription":
            if a.host:
                if (
                    a.action not in ("publish", "rollback", "prune", "status")
                    or not a.publish_config
                ):
                    raise Error(
                        "SSH subscription requires publish/rollback/status/prune with --publish-config"
                    )
                from .remote import execute

                files = {"publish.json": a.publish_config}
                if a.access_file:
                    files["access.json"] = a.access_file
                args = [
                    "subscription",
                    a.action,
                    "--publish-config",
                    "__VRK_UPLOAD__/publish.json",
                ]
                if a.access_file:
                    args += ["--access-file", "__VRK_UPLOAD__/access.json"]
                if a.action == "prune":
                    args += ["--keep", str(a.keep), "--older-than-days", str(a.older_than_days)]
                    if a.execute:
                        args += ["--execute"]
                if a.revision:
                    args += ["--revision", a.revision]
                if a.action == "publish":
                    if not a.bundle:
                        raise Error("publish requires --bundle")
                    files["bundle"] = a.bundle
                    args += ["--bundle", "__VRK_UPLOAD__/bundle"]
                if a.allow_candidates:
                    args += ["--allow-candidates"]
                print(execute(a.host, args, jump=a.jump, extra_files=files), end="")
                return
            from .subscription import build, access
            from .publishing import publish, rollback, prune, status

            if a.action == "token":
                if not a.access_file:
                    raise Error("token requires --access-file")
                access(a.access_file, a.rotate)
                print("Private access file saved; publish to activate token changes")
                return
            if a.action == "status":
                if not a.publish_config:
                    raise Error("status requires --publish-config")
                print(encode(status(read(a.publish_config))))
                return
            if a.action == "prune":
                if not a.publish_config:
                    raise Error("prune requires --publish-config")
                print(encode(prune(read(a.publish_config), a.keep, a.older_than_days, a.execute)))
                return
            if a.action == "build":
                if not all((a.catalog, a.output, a.base_url)) or (
                    "clash" in a.formats.split(",") and not a.mihomo
                ):
                    raise Error("build requires --catalog, --output, --base-url, --mihomo")
                result = build(
                    read(a.catalog),
                    Path(a.catalog).parent,
                    a.output,
                    a.base_url,
                    a.access_file,
                    a.mihomo,
                    a.include_candidates,
                    name=a.name,
                    formats=a.formats,
                    access_mode=a.access_mode,
                )
            else:
                if not a.publish_config or (a.action == "publish" and not a.bundle):
                    raise Error(
                        "publication requires --publish-config and publish requires --bundle"
                    )
                cfg = read(a.publish_config)
                result = (
                    publish(cfg, a.bundle, a.access_file, a.allow_candidates)
                    if a.action == "publish"
                    else rollback(cfg, a.access_file, a.allow_candidates, a.revision)
                )
            print(encode(result))
            return
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
        if getattr(a, "host", None) and getattr(a, "verify_cases", None):
            from .acceptance import remote_apply

            result = remote_apply(a, read(a.verify_cases))
            print(encode(result))
            return 0 if result["acceptance"]["decision"] == "passed" else 1
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
            if a.command == "rollback":
                if a.snapshot:
                    args += ["--snapshot", a.snapshot]
                if a.expected_generation:
                    args += ["--expected-generation", a.expected_generation]
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
                        "service_impact": deploy.impact(c, old, read(a.lock or LOCK)),
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
            result = deploy.apply(
                read(a.config),
                a.secrets,
                a.lock,
                read(a.verify_cases) if a.verify_cases else None,
                a.verify_output,
            )
            if a.verify_cases:
                decision = Path(a.verify_output) / "decision.json"
                if not decision.exists() or read(decision).get("decision") != "passed":
                    return 1
            return
        if a.command == "backup":
            deploy.backup()
            return
        if a.command == "rollback":
            deploy.rollback(a.snapshot, a.expected_generation)
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

            if Path(a.output).exists():
                raise Error(
                    "benchmark output exists; preserve prior evidence and choose a new path"
                )
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
                    connect_ip=a.connect_ip,
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
