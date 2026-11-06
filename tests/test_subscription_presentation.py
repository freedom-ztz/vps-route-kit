import copy
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_subscription import inventory
from vrk import catalog, __version__
from vrk.subscription import build, locked_rule
from vrk.publishing import validate_bundle
from vrk.util import Error, digest, read


class PresentationTests(unittest.TestCase):
    def test_direct_path_precedes_relay_within_same_exit_country(self):
        c = inventory()
        c["routes"][0]["id"] = "aaa-relay"
        direct = copy.deepcopy(c["routes"][0])
        direct.update(id="zzz-direct", path=["exit"])
        c["routes"].append(direct)
        catalog.validate(c)
        self.assertEqual(
            [r["id"] for r in catalog.selected(c, ".", True)], ["zzz-direct", "aaa-relay"]
        )
        direct["priority"] = 200
        self.assertEqual(
            [r["id"] for r in catalog.selected(c, ".", True)], ["aaa-relay", "zzz-direct"]
        )

    def test_display_name_preserves_network_evidence_but_not_network_changes(self):
        c = inventory()
        route = c["routes"][0]
        before = catalog.fingerprint(c, route)
        route["display_name"] = "🇸🇬 新加坡·V"
        route["priority"] = 10
        catalog.validate(c)
        self.assertEqual(before, catalog.fingerprint(c, route))
        self.assertEqual(catalog.proxies(c, [route])[1], ["🇸🇬 新加坡·V"])
        c["nodes"]["node"]["port"] += 1
        self.assertNotEqual(before, catalog.fingerprint(c, route))

    def test_invalid_or_conflicting_labels_are_rejected(self):
        for label in [
            "",
            " 自动",
            "自动",
            "REJECT",
            "GLOBAL",
            "PASS",
            "REJECT-DROP",
            "a\nb",
            "_carrier-other",
            "_vrk-hop-other",
        ]:
            c = inventory()
            c["routes"][0]["display_name"] = label
            with self.subTest(label=label), self.assertRaises(Error):
                catalog.validate(c)
        c = inventory()
        c["routes"][0]["display_name"] = "same"
        second = copy.deepcopy(c["routes"][0])
        second["id"] = "second"
        c["routes"].append(second)
        with self.assertRaises(Error):
            catalog.proxies(c, c["routes"])

    def test_candidates_only_in_desktop_manual_group_and_country_from_metadata(self):
        c = inventory()
        c["routes"][0]["display_name"] = "🇸🇬 新加坡·V"
        for key, country, label in [("hk", "HK", "手动出口·V"), ("candidate", "US", "🇺🇸 美国·X")]:
            route = copy.deepcopy(c["routes"][0])
            route.update(id=key, exit_country=country, display_name=label)
            c["routes"].append(route)
        with (
            tempfile.TemporaryDirectory() as folder,
            patch("vrk.catalog.accepted", side_effect=lambda c, r, base: r["id"] != "candidate"),
            patch("vrk.subscription.locked_rule", side_effect=["+.example.cn\n", "192.0.2.0/24\n"]),
            patch("vrk.subscription.run", return_value=SimpleNamespace(returncode=0)),
        ):
            out = Path(folder) / "release"
            build(
                c,
                folder,
                out,
                "https://sub.example.com",
                None,
                "/mihomo",
                access_mode="public",
                manual_candidates=True,
            )
            m = validate_bundle(out)
            desktop = read(out / "desktop.json")
            self.assertTrue(all(p["proxy"] == "DIRECT" for p in desktop["rule-providers"].values()))
            provider = read(out / "nodes.json")
            self.assertEqual(len(desktop["proxies"]), 3)
            self.assertEqual(len(provider["proxies"]), 2)
            self.assertEqual(len(m["routes"]), 2)
            self.assertEqual(m["formats"]["v2ray"]["nodes"], 2)
            groups = {g["name"]: g for g in desktop["proxy-groups"]}
            self.assertEqual(groups["自动"]["proxies"], ["REJECT", "🇸🇬 新加坡·V"])
            self.assertEqual(groups["测试"]["proxies"], ["REJECT", "🇺🇸 美国·X"])
            self.assertEqual(groups["外网"]["proxies"][0], "自动")
            self.assertNotIn("🇺🇸 美国·X", groups["手动"]["proxies"])
            example = read(out / "openwrt-example.json")
            self.assertIn("新加坡", example["proxy-groups"][1]["filter"])
            self.assertNotIn("手动出口", example["proxy-groups"][1]["filter"])
            self.assertFalse(m["candidate_only"])

    def test_manual_candidates_does_not_allow_candidate_only_or_v2ray_only(self):
        for candidates, formats in [(True, "clash,v2ray"), (False, "v2ray")]:
            with tempfile.TemporaryDirectory() as folder, self.assertRaises(Error):
                build(
                    inventory(),
                    folder,
                    Path(folder) / "out",
                    "https://sub.example.com",
                    None,
                    None,
                    candidates,
                    formats=formats,
                    manual_candidates=True,
                )

    def test_rule_download_identifies_application_and_keeps_hash_validation(self):
        class Response:
            url = "https://example.com/rule"

            def read(self, limit):
                return b"+.example.cn\n"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        with patch("urllib.request.urlopen", return_value=Response()) as request:
            locked_rule({"url": Response.url, "sha256": digest(b"+.example.cn\n")}, "domains")
            value = request.call_args.args[0]
            self.assertEqual(value.get_header("User-agent"), "vps-route-kit/" + __version__)
            self.assertEqual(value.full_url, Response.url)
