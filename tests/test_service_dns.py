import copy
import unittest
from vrk.config import sample, validate
from vrk import deploy
from vrk.render import render
from vrk.util import Error
from test_render import SECRET


class ServiceDNSTests(unittest.TestCase):
    def test_invalid_resolvers_are_rejected_before_deployment(self):
        for value in [
            [],
            ["dns.example.com"],
            ["127.0.0.1:53"],
            ["::1"],
            ["0.0.0.0"],
            ["224.0.0.1"],
            ["255.255.255.255"],
            ["127.0.0.1", "127.0.0.1"],
            ["127.0.0.1\nExecStart=/bad"],
        ]:
            with self.subTest(value=value):
                c = sample()
                c["service_dns"] = {"xray": value}
                with self.assertRaises(Error):
                    validate(c)
        c = sample()
        c["service_dns"] = {"unknown": ["127.0.0.1"]}
        with self.assertRaises(Error):
            validate(c)

    def test_dns_is_explicit_and_generated_per_component(self):
        c = sample()
        c["service_dns"] = {"xray": ["127.0.0.1"], "hysteria": ["192.0.2.53", "192.0.2.54"]}
        files, _ = render(validate(c), SECRET)
        self.assertEqual(files["resolv-xray.conf"], "nameserver 127.0.0.1\n")
        self.assertEqual(
            files["resolv-hysteria.conf"], "nameserver 192.0.2.53\nnameserver 192.0.2.54\n"
        )
        self.assertNotIn("resolv-realm.conf", files)
        files, _ = render(validate(sample()), SECRET)
        self.assertFalse(any(x.startswith("resolv-") for x in files))
        plain, _ = render(validate(sample()), SECRET)
        configured = sample()
        configured["service_dns"] = {"xray": ["127.0.0.1"]}
        configured, _ = render(validate(configured), SECRET)
        self.assertEqual(plain["xray.json"], configured["xray.json"])

    def test_unit_uses_native_readonly_mount_without_host_dns_mutation(self):
        content = deploy.unit(
            "xray", "/opt/core", ["run"], resolver_file="/var/lib/vrk/current/resolv-xray.conf"
        )
        self.assertIn(
            'BindReadOnlyPaths="/var/lib/vrk/current/resolv-xray.conf:/etc/resolv.conf"', content
        )
        self.assertNotIn("ExecStartPre", content)
        self.assertNotIn("BindReadOnlyPaths", deploy.unit("realm", "/opt/realm", []))

    def test_only_configured_core_restarts_when_dns_is_added_changed_or_removed(self):
        before = sample()
        before["relays"] = [
            {
                "id": "forward",
                "listen": "0.0.0.0",
                "port": 26443,
                "remote": "192.0.2.20",
                "remote_port": 24443,
                "transports": ["tcp", "udp"],
            }
        ]
        added = copy.deepcopy(before)
        added["service_dns"] = {"xray": ["127.0.0.1"]}
        changed = copy.deepcopy(added)
        changed["service_dns"]["xray"] = ["192.0.2.53"]
        for a, b in [(before, added), (added, changed), (added, before)]:
            with self.subTest(before=a.get("service_dns"), after=b.get("service_dns")):
                old = {"config": validate(a), "versions": {}}
                actions = {
                    x["service"]: x["action"]
                    for x in deploy.impact(validate(b), old, {})["services"]
                }
                self.assertEqual(actions["vrk-xray"], "restart")
                self.assertEqual(actions["vrk-realm"], "unchanged")
                self.assertEqual(actions["vrk-hy-hy2"], "unchanged")

    def test_plan_and_apply_share_resolver_file_dependencies(self):
        c = sample()
        c["service_dns"] = {"xray": ["127.0.0.1"]}
        files, args = render(validate(c), SECRET, str(deploy.ROOT))
        names = deploy.service_files(c, *args["vrk-xray"])
        self.assertIn("resolv-xray.conf", names)
        self.assertIn("xray.json", names)
        self.assertTrue(all(n in files for n in names))
        self.assertNotIn("resolv-xray.conf", deploy.service_files(c, *args["vrk-hy-hy2"]))
