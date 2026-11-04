import json
import unittest
from vrk.config import sample, validate
from vrk.render import render
from vrk.export import export
from vrk.util import Error

SECRET = {
    "primary": {
        "uuid": "a6feb21e-46c0-493b-befd-43722593cb29",
        "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "short_id": "abcd",
    },
    "hy2": {"password": "test-password-do-not-use"},
}


class RenderTests(unittest.TestCase):
    def test_flow_belongs_only_to_vision(self):
        f, _ = render(validate(sample()), SECRET)
        ib = json.loads(f["xray.json"])["inbounds"]
        self.assertEqual(ib[0]["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        self.assertNotIn("flow", ib[1]["settings"]["clients"][0])
        self.assertEqual(ib[1]["streamSettings"]["xhttpSettings"]["mode"], "stream-one")

    def test_rules_order_and_explicit_default(self):
        c = sample()
        c["routing"] = {
            "default": "reject",
            "rules": [
                {"domain": ["example.com"], "action": "local"},
                {"cidr": ["192.0.2.1/32"], "action": "reject"},
            ],
        }
        f, _ = render(validate(c), SECRET)
        r = json.loads(f["xray.json"])["routing"]["rules"]
        self.assertEqual([x["outboundTag"] for x in r], ["local", "reject", "reject"])
        self.assertEqual(r[0]["domain"], ["full:example.com"])
        self.assertEqual(
            json.loads(f["hy-hy2.json"])["outbounds"][0]["socks5"]["addr"], "127.0.0.1:18080"
        )

    def test_hysteria_direct_without_bridge(self):
        f, s = render(validate(sample()), SECRET)
        d = json.loads(f["hy-hy2.json"])
        self.assertEqual(d["outbounds"][0]["type"], "direct")
        self.assertNotIn("bandwidth", d)
        self.assertEqual(d["congestion"]["bbrProfile"], "standard")

    def test_export_preserves_endpoint_identity(self):
        d = export(sample(), SECRET, "mihomo", address="192.0.2.1", ports={"hy2": 26443})
        h = d["proxies"][2]
        self.assertEqual(h["sni"], "hy2.example.com")
        self.assertEqual(h["server"], "192.0.2.1")
        self.assertEqual(h["port"], 26443)
        self.assertFalse(h["skip-cert-verify"])

    def test_prefix_does_not_disable_port_mapping(self):
        for kind in ("mihomo", "nodes", "hysteria", "uri"):
            with self.subTest(kind=kind):
                result = export(
                    sample(),
                    SECRET,
                    kind,
                    address="192.0.2.1",
                    ports={"hy2": 26443},
                    listener="hy2",
                    name_prefix="us-via-jp-",
                )
                if kind == "mihomo":
                    self.assertEqual(result["proxies"][0]["port"], 26443)
                elif kind == "nodes":
                    self.assertEqual(result["nodes"]["us-via-jp-hy2"]["port"], 26443)
                elif kind == "hysteria":
                    self.assertEqual(result["server"], "192.0.2.1:26443")
                else:
                    self.assertIn(":26443/", result)

    def test_xhttp_client_prefix_and_mapping_preserve_reality_identity(self):
        r = export(
            sample(),
            SECRET,
            "xray",
            address="192.0.2.1",
            ports={"xhttp": 27443},
            listener="xhttp",
            name_prefix="us-via-jp-",
        )
        n = r["outbounds"][0]
        self.assertEqual(n["tag"], "us-via-jp-xhttp")
        self.assertEqual(n["settings"]["vnext"][0]["port"], 27443)
        self.assertEqual(n["streamSettings"]["realitySettings"]["serverName"], "www.example.com")

    def test_native_mihomo_carrier_export_preserves_final_endpoint(self):
        d = export(
            sample(),
            SECRET,
            "mihomo",
            listener="hy2",
            name_prefix="us-",
            dialer_proxy="新加坡直连线路",
        )
        n = d["proxies"][0]
        self.assertEqual(n["dialer-proxy"], "新加坡直连线路")
        self.assertEqual(n["sni"], "hy2.example.com")
        self.assertFalse(n["skip-cert-verify"])
        with self.assertRaises(Error):
            export(sample(), SECRET, "uri", dialer_proxy="parent")
        with self.assertRaises(Error):
            export(sample(), SECRET, "mihomo", listener="hy2", dialer_proxy="hy2")

    def test_invalid_port_map_rejected(self):
        for ports in [[], {"missing": 443}, {"vision": 70000}]:
            with self.subTest(ports=ports), self.assertRaises(Error):
                export(sample(), SECRET, "mihomo", ports=ports)

    def test_xray_rejects_unsupported_export(self):
        with self.assertRaises(Error):
            export(sample(), SECRET, "xray")

    def test_node_prefix_keeps_credentials_namespaced(self):
        d = export(sample(), SECRET, "nodes", name_prefix="us-")
        self.assertEqual(d["nodes"]["us-vision"]["secret"], "us-primary")
        self.assertIn("us-primary", d["secrets"])
        self.assertNotIn("private_key", d["secrets"]["us-primary"])

    def test_uri_encoding(self):
        s = {**SECRET, "hy2": {"password": "a@b#c"}}
        uri = export(sample(), s, "uri", listener="hy2")
        self.assertIn("a%40b%23c@", uri)

    def test_internal_hysteria_client_only_for_used_nodes(self):
        c = sample()
        c["nodes"] = {
            "remote": {
                "protocol": "hysteria2",
                "address": "192.0.2.2",
                "port": 443,
                "server_name": "remote.example.com",
                "secret": "hy2",
            }
        }
        f, s = render(c, SECRET)
        self.assertNotIn("vrk-hy-client-remote", s)
        c["routing"]["default"] = "node:remote"
        f, s = render(validate(c), SECRET)
        self.assertIn("vrk-hy-client-remote", s)
        self.assertEqual(
            json.loads(f["hy-client-remote.json"])["socks5"]["listen"], "127.0.0.1:18100"
        )
