import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from vrk import catalog
from vrk.config import sample, validate
from vrk.export import export
from vrk.subscription import build, locked_rule, groups
from vrk.publishing import configuration, validate_bundle, publish, rollback
from vrk.util import Error, atomic, digest, read
from vrk.deploy import impact


def inventory():
    c = validate(sample())
    c["listeners"] = c["listeners"][:1]
    auth = {
        "primary": {
            "uuid": "00000000-0000-4000-8000-000000000001",
            "public_key": "A" * 43,
            "short_id": "abcd",
        }
    }
    node = export(c, auth, "mihomo")["proxies"][0]
    return {
        "schema_version": 1,
        "hosts": {"entry": {"address": "203.0.113.10"}, "exit": {"address": "192.0.2.20"}},
        "nodes": {"node": node},
        "routes": [
            {
                "id": "test",
                "node": "node",
                "path": ["entry", "exit"],
                "exit_host": "exit",
                "exit_country": "SG",
                "expected_exit_ipv4": "192.0.2.20",
            }
        ],
    }


def bundle(d, c=None):
    c = c or inventory()
    with (
        patch("vrk.subscription.locked_rule", side_effect=["+.example.cn\n", "192.0.2.0/24\n"]),
        patch("vrk.subscription.run", return_value=SimpleNamespace(returncode=0)),
    ):
        build(
            c,
            d,
            Path(d) / "bundle",
            "https://sub.example.com:18543",
            Path(d) / "access.json",
            "/mihomo",
            True,
        )
    return Path(d) / "bundle"


class CatalogTests(unittest.TestCase):
    def test_shared_hosts_report_path_redundancy_and_never_assumes_pass(self):
        c = inventory()
        r = copy.deepcopy(c["routes"][0])
        r["id"] = "second"
        c["routes"].append(r)
        result = catalog.report(c)
        self.assertEqual(result["shared_dependencies"]["exit"], ["test", "second"])
        self.assertFalse(result["routes"][0]["accepted"])
        with self.assertRaises(Error):
            catalog.selected(c, ".")

    def test_invalid_path_carrier_country_rejected(self):
        for kind in ("cycle", "carrier", "country", "unknown"):
            c = inventory()
            if kind == "cycle":
                c["routes"][0]["path"] = ["entry", "exit", "entry"]
            if kind == "carrier":
                c["nodes"]["node"]["dialer-proxy"] = "node"
            if kind == "country":
                c["routes"][0]["exit_country"] = "ZZ"
            if kind == "unknown":
                c["routes"][0]["node"] = "missing"
            with self.subTest(kind=kind), self.assertRaises(Error):
                catalog.validate(c)

    def test_acceptance_requires_matching_egress_and_full_stability(self):
        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            r = c["routes"][0]
            r["acceptance"] = {"diagnosis": "d.json", "stability": "s.json"}
            atomic(
                Path(d) / "d.json",
                {
                    "completed": True,
                    "routes": {
                        "test": {
                            "binding": catalog.binding(c, r, [], "batch", {"mihomo": "1.19.32"}),
                            "ok": True,
                            "exercises": {
                                k: {"ok": True}
                                for k in ("stream", "idle", "download", "upload", "udp")
                            },
                            "fingerprint": catalog.fingerprint(c, r),
                            "exit_ipv4": r["expected_exit_ipv4"],
                        }
                    },
                },
            )
            s = {
                "bindings": {"test": catalog.binding(c, r, [], "batch", {"mihomo": "1.19.32"})},
                "completed": True,
                "all_declared_passed": True,
                "elapsed_seconds": 1800,
                "cases": {
                    "test/a": {"checks": 60, "failures": 0},
                    "test/b": {"checks": 60, "failures": 0},
                },
            }
            atomic(Path(d) / "s.json", s)
            self.assertTrue(catalog.accepted(c, r, d))
            c["nodes"]["node"]["port"] += 1
            self.assertFalse(catalog.accepted(c, r, d))


class SubscriptionTests(unittest.TestCase):
    def test_desktop_and_openwrt_have_distinct_ownership(self):
        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            c["company"] = {
                "domains": ["corp.example.com"],
                "cidrs": ["10.0.0.0/8"],
                "dns": ["192.168.2.1"],
            }
            b = bundle(d, c)
            full = read(b / "desktop.json")
            router = read(b / "openwrt-example.json")
            self.assertEqual(set(router), {"proxy-providers", "proxy-groups"})
            self.assertFalse(full["allow-lan"])
            self.assertFalse(full["tun"]["enable"])
            self.assertEqual(full["bind-address"], "127.0.0.1")
            self.assertEqual(
                full["dns"]["nameserver-policy"]["+.corp.example.com"], ["192.168.2.1"]
            )
            auto = full["proxy-groups"][1]
            self.assertEqual(auto["proxies"], ["REJECT", "SG-test"])
            self.assertNotIn("DIRECT", auto["proxies"])
            self.assertEqual(auto["timeout"], 8000)
            self.assertEqual(
                full["dns"]["nameserver-policy"]["www.gstatic.com"],
                ["https://dns.alidns.com/dns-query"],
            )
            manifest = (b / "manifest.json").read_text()
            self.assertNotIn(c["nodes"]["node"]["uuid"], manifest)
            self.assertNotIn(read(Path(d) / "access.json")["token"], manifest)
            self.assertTrue(read(b / "manifest.json")["candidate_only"])

    def test_rule_failure_cannot_create_release_or_overwrite_previous(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("vrk.subscription.locked_rule", side_effect=Error("checksum")):
                with self.assertRaises(Error):
                    build(
                        inventory(),
                        d,
                        Path(d) / "bundle",
                        "https://sub.example.com",
                        Path(d) / "a.json",
                        "/mihomo",
                        True,
                    )
            self.assertFalse((Path(d) / "bundle").exists())

    def test_invalid_mihomo_rejects_entire_bundle(self):
        with (
            tempfile.TemporaryDirectory() as d,
            patch("vrk.subscription.locked_rule", return_value="+.example.com\n"),
            patch("vrk.subscription.run", return_value=SimpleNamespace(returncode=1)),
        ):
            with self.assertRaises(Error):
                build(
                    inventory(),
                    d,
                    Path(d) / "bundle",
                    "https://sub.example.com",
                    Path(d) / "a.json",
                    "/mihomo",
                    True,
                )
            self.assertFalse((Path(d) / "bundle").exists())

    def test_hash_validation_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            b = bundle(d)
            atomic(b / "nodes.json", {"proxies": []})
            with self.assertRaises(Error):
                validate_bundle(b)

    def test_locked_rules_require_exact_bytes(self):
        response = SimpleNamespace(
            url="https://example.com/cn", read=lambda _: b"+.example.cn\n", __enter__=lambda s: s
        )

        class Response:
            url = "https://example.com/cn"

            def read(self, limit):
                return b"+.example.cn\n"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        with patch("urllib.request.urlopen", return_value=Response()):
            with self.assertRaises(Error):
                locked_rule({"url": "https://example.com/cn", "sha256": "a" * 64}, "domains")
            self.assertEqual(
                locked_rule(
                    {"url": "https://example.com/cn", "sha256": digest(b"+.example.cn\n")},
                    "domains",
                ),
                "+.example.cn\n",
            )

    def test_web_configuration_scopes_files_and_suppresses_url_logging(self):
        c = {
            "root": "/var/lib/vrk-subscriptions",
            "domain": "sub.example.com",
            "port": 18543,
            "base_url": "https://sub.example.com:18543",
            "certificate": "/cert",
            "key": "/key",
        }
        text = configuration(c, "a" * 43)
        self.assertIn("access_log off;", text)
        self.assertIn("location / { return 404; }", text)
        self.assertNotIn("listen 443", text)
        c["base_url"] = "https://other.example.com:18543"
        with self.assertRaises(Error):
            configuration(c, "a" * 43)

    def test_group_empty_provider_still_has_explicit_reject(self):
        g = groups([], "vrk")[1]
        self.assertEqual(g["proxies"], ["REJECT"])
        self.assertEqual(g["filter"], "^(SG|JP|US)-")

    def test_hong_kong_exit_is_manual_only_in_both_delivery_modes(self):
        c = inventory()
        c["routes"][0]["exit_country"] = "HK"
        catalog.validate(c)
        nodes, names = catalog.proxies(c, c["routes"])
        self.assertEqual(nodes[0]["name"], "HK-test")
        automatic, manual = groups(["SG-primary", *names])[1:]
        self.assertEqual(automatic["proxies"], ["REJECT", "SG-primary"])
        self.assertIn("HK-test", manual["proxies"])
        automatic, manual = groups([], "vrk")[1:]
        self.assertEqual(automatic["filter"], "^(SG|JP|US)-")
        self.assertEqual(manual["filter"], "^(SG|JP|US|HK)-")

    def test_hong_kong_only_has_no_automatic_proxy_fallback(self):
        automatic = groups(["HK-test"])[1]
        self.assertEqual(automatic["proxies"], ["REJECT"])

    def test_xray_change_exposes_all_shared_listeners(self):
        c = validate(sample())
        old = {"config": copy.deepcopy(c), "versions": {}}
        c["listeners"][0]["port"] += 1
        result = impact(c, old, {})
        xray = next(s for s in result["services"] if s["service"] == "vrk-xray")
        self.assertEqual(xray["action"], "restart")
        self.assertEqual(xray["affected_listeners"], ["vision", "xhttp"])
        hy = next(s for s in result["services"] if s["service"] == "vrk-hy-hy2")
        self.assertEqual(hy["action"], "unchanged")


class DualFormatTests(unittest.TestCase):
    def test_v2ray_feed_is_base64_standard_links_and_excludes_unexpressible_chains(self):
        import base64
        import urllib.parse

        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            c["nodes"]["chained"] = copy.deepcopy(c["nodes"]["node"])
            c["nodes"]["chained"]["dialer-proxy"] = "node"
            route = copy.deepcopy(c["routes"][0])
            route.update(id="chained", node="chained")
            c["routes"].append(route)
            b = bundle(d, c)
            links = (
                base64.b64decode((b / "v2ray.txt").read_text(), validate=False)
                .decode()
                .splitlines()
            )
            self.assertEqual(len(links), 1)
            u = urllib.parse.urlsplit(links[0])
            q = urllib.parse.parse_qs(u.query)
            self.assertEqual(u.scheme, "vless")
            self.assertEqual(q["flow"], ["xtls-rprx-vision"])
            self.assertEqual(q["security"], ["reality"])
            self.assertEqual(
                read(b / "manifest.json")["formats"]["v2ray"]["excluded_client_chains"],
                ["SG-chained"],
            )
            feed = read(b / "nodes.json")["proxies"]
            self.assertTrue(any(n.get("dialer-proxy") == "_vrk-hop-node" for n in feed))
            groups = read(b / "openwrt-example.json")["proxy-groups"]
            self.assertTrue(any(g["name"] == "_vrk-hop-node" for g in groups))

    def test_all_client_chains_rejects_dual_publication_instead_of_empty_feed(self):
        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            c["nodes"]["carrier"] = copy.deepcopy(c["nodes"]["node"])
            c["nodes"]["node"]["dialer-proxy"] = "carrier"
            with self.assertRaisesRegex(Error, "no V2Ray-shareable"):
                bundle(d, c)

    def test_hysteria_and_xhttp_link_parameters_are_preserved(self):
        import urllib.parse
        from vrk.export import mihomo_uri

        hy = {
            "name": "US-hy2",
            "type": "hysteria2",
            "server": "192.0.2.20",
            "port": 24443,
            "password": "a:/@?特殊",
            "sni": "hy2.example.com",
        }
        u = urllib.parse.urlsplit(mihomo_uri(hy).strip())
        self.assertEqual(urllib.parse.unquote(u.username), hy["password"])
        self.assertEqual(urllib.parse.parse_qs(u.query)["insecure"], ["0"])
        n = inventory()["nodes"]["node"]
        n.update(
            name="US-xhttp",
            network="xhttp",
            **{"xhttp-opts": {"path": "/a b", "mode": "stream-one"}},
        )
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(mihomo_uri(n).strip()).query)
        self.assertEqual(q["type"], ["xhttp"])
        self.assertEqual(q["path"], ["/a b"])
        self.assertNotIn("flow", q)

    def test_empty_pid_from_nginx_test_is_not_a_running_service(self):
        from vrk.publishing import running

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "nginx.pid").write_text("")
            self.assertFalse(running(d))

    def test_single_public_site_failure_never_triggers_rollback(self):
        from vrk.deploy import acceptance_decision

        before = {
            "all_declared_passed": True,
            "cases": {"test/a": {"failures": 0}, "test/b": {"failures": 0}},
        }
        after = {
            "all_declared_passed": False,
            "cases": {"test/a": {"failures": 1}, "test/b": {"failures": 0}},
        }
        self.assertEqual(
            acceptance_decision(before, after)["decision"], "undetermined_external_failure"
        )
        after["cases"]["test/b"]["failures"] = 1
        self.assertEqual(acceptance_decision(before, after)["decision"], "rollback")


class PublicationTransactionTests(unittest.TestCase):
    def fixture(self, d):
        root = Path(d)
        cert = root / "cert"
        cert.write_text("fixture certificate")
        key = root / "key"
        key.write_text("fixture key")
        return {
            "root": str(root / "web"),
            "domain": "sub.example.com",
            "port": 18543,
            "listen": "127.0.0.1",
            "base_url": "https://sub.example.com:18543",
            "certificate": str(cert),
            "key": str(key),
            "user": "www-data",
            "nginx": "/fixture/nginx",
        }

    def patches(self, d):
        from contextlib import ExitStack
        import os

        stack = ExitStack()
        stack.enter_context(patch("vrk.publishing.os.geteuid", return_value=0))
        stack.enter_context(patch("vrk.publishing.os.chown"))
        stack.enter_context(patch("vrk.publishing.health"))
        stack.enter_context(
            patch("vrk.publishing.grp.getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid()))
        )
        units = Path(d) / "units"
        units.mkdir()
        stack.enter_context(patch("vrk.publishing.SYSTEMD_UNITS", units))
        rotation = Path(d) / "logrotate"
        rotation.mkdir()
        stack.enter_context(patch("vrk.publishing.LOGROTATE", rotation))
        run = stack.enter_context(
            patch(
                "vrk.publishing.run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout="Hostname sub.example.com does match certificate\n",
                    stderr="",
                ),
            )
        )
        return stack, run

    def test_publish_preserves_old_release_on_nginx_failure_and_applies_worker_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            b = bundle(d)
            cfg = self.fixture(d)
            stack, runner = self.patches(d)
            with stack:
                publish(cfg, b, Path(d) / "access.json", True)
                web = Path(cfg["root"])
                old = (web / "current").resolve()
                self.assertEqual((web / "releases").stat().st_mode & 0o777, 0o750)

                def failed(args, **kw):
                    return SimpleNamespace(
                        returncode=1 if "-t" in args else 0,
                        stdout="Hostname sub.example.com does match certificate\n",
                        stderr="",
                    )

                runner.side_effect = failed
                with self.assertRaises(Error):
                    publish(cfg, b, Path(d) / "access.json", True)
                self.assertEqual((web / "current").resolve(), old)
                self.assertEqual(
                    read(web / "owner.json")["revision"], read(old / "manifest.json")["revision"]
                )

    def test_rollback_does_not_reenable_revoked_token(self):
        from vrk.subscription import access

        with tempfile.TemporaryDirectory() as d:
            first = bundle(d)
            second_root = Path(d) / "second"
            second_root.mkdir()
            c = inventory()
            c["nodes"]["node"]["port"] += 1
            second = bundle(second_root, c)
            cfg = self.fixture(d)
            token_file = Path(d) / "access.json"
            old = access(token_file)
            stack, _ = self.patches(d)
            with stack:
                publish(cfg, first, token_file, True)
                new = access(token_file, True)
                publish(cfg, second, token_file, True)
                rollback(cfg, token_file, True)
                config = (Path(cfg["root"]) / "nginx.conf").read_text()
                self.assertIn("/" + new + "/v2ray.txt", config)
                self.assertNotIn("/" + old + "/", config)
                desktop = (Path(cfg["root"]) / "current/desktop.json").read_text()
                self.assertIn("/" + new + "/", desktop)
                self.assertNotIn("/" + old + "/", desktop)

    def test_wrong_certificate_identity_stops_before_directory_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            b = bundle(d)
            cfg = self.fixture(d)
            stack, runner = self.patches(d)
            with stack:
                runner.return_value = SimpleNamespace(
                    returncode=0, stdout="Hostname does NOT match certificate", stderr=""
                )
                with self.assertRaises(Error):
                    publish(cfg, b, Path(d) / "access.json", True)
                self.assertFalse(Path(cfg["root"]).exists())
