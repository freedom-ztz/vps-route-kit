import copy
import unittest
from vrk.config import sample, validate
from vrk.util import Error


class ConfigTests(unittest.TestCase):
    def test_default(self):
        self.assertEqual(len(validate(sample())["_bindings"]), 3)

    def test_bad_config_cases(self):
        for field, value in [("schema_version", 2), ("address", "host; touch /tmp/x")]:
            with self.subTest(field=field):
                c = sample()
                c[field] = value
                with self.assertRaises(Error):
                    validate(c)

    def test_ipv6_rejected_explicitly(self):
        c = sample()
        c["listeners"][0]["listen"] = "::"
        with self.assertRaises(Error):
            validate(c)

    def test_plaintext_credentials_in_config_rejected(self):
        c = sample()
        c["listeners"][0]["password"] = "do-not-store-here"
        with self.assertRaises(Error):
            validate(c)

    def test_hysteria_client_reserves_only_fixed_tcp_socket(self):
        c = sample()
        c["nodes"] = {
            "remote": {
                "protocol": "hysteria2",
                "address": "192.0.2.2",
                "port": 443,
                "server_name": "remote.example.com",
                "secret": "remote",
            }
        }
        c["routing"]["default"] = "node:remote"
        bindings = validate(c)["_bindings"]
        self.assertIn(["tcp", "127.0.0.1", 18100], bindings)
        self.assertNotIn(["udp", "127.0.0.1", 18100], bindings)

    def test_missing_default_rejected(self):
        c = sample()
        c["routing"].pop("default")
        with self.assertRaises(Error):
            validate(c)

    def test_conflicting_ports_rejected(self):
        c = sample()
        c["listeners"][1]["port"] = 24443
        with self.assertRaises(Error):
            validate(c)

    def test_unknown_node_rejected(self):
        c = sample()
        c["routing"]["default"] = "node:missing"
        with self.assertRaises(Error):
            validate(c)

    def test_mixed_match_rejected(self):
        c = sample()
        c["routing"]["rules"] = [
            {"domain": ["example.com"], "cidr": ["192.0.2.0/24"], "action": "local"}
        ]
        with self.assertRaises(Error):
            validate(c)

    def test_cidr_and_suffix(self):
        c = sample()
        c["routing"]["rules"] = [
            {"suffix": ["example.com"], "action": "reject"},
            {"cidr": ["192.0.2.0/24"], "action": "local"},
        ]
        self.assertTrue(validate(c))

    def test_loop_rejected(self):
        c = sample()
        c["relays"] = [{"id": "loop", "port": 29999, "remote": c["address"], "remote_port": 29999}]
        with self.assertRaises(Error):
            validate(c)

    def test_recursive_node_chain_rejected(self):
        c = sample()
        c["nodes"] = {"loop": {"via": "loop"}}
        with self.assertRaises(Error):
            validate(c)

    def test_path_traversal_identifier(self):
        c = sample()
        c["listeners"][0]["id"] = "../../xray"
        with self.assertRaises(Error):
            validate(c)
