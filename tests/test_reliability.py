"""Regressions for deployment identity, route evidence and subscription transactions."""

import copy
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import unittest
from vrk import catalog, deploy
from vrk.config import sample, validate
from vrk.render import render
from vrk.util import atomic, read, Error
from vrk.subscription import build
from vrk.publishing import publish, rollback
from test_subscription import inventory, bundle
import test_subscription as fixtures


class ReliabilityTests(unittest.TestCase):
    def test_omitted_rules_do_not_require_nonexistent_bridge(self):
        c = sample()
        c["listeners"] = [c["listeners"][2]]
        c["routing"] = {"default": "local"}
        validate(c)
        files, _ = render(c, {"hy2": {"password": "test"}})
        self.assertNotIn("xray.json", files)
        self.assertFalse(any(b[2] == 18080 for b in c["_bindings"]))

    def test_unrelated_nodes_do_not_invalidate_evidence(self):
        c = inventory()
        r = c["routes"][0]
        before = catalog.fingerprint(c, r)
        c["nodes"]["unrelated"] = copy.deepcopy(c["nodes"]["node"])
        c["nodes"]["unrelated"]["port"] += 1
        self.assertEqual(before, catalog.fingerprint(c, r))
        c["nodes"]["node"]["port"] += 1
        self.assertNotEqual(before, catalog.fingerprint(c, r))

    def test_evidence_requires_same_batch_and_completed_diagnosis(self):
        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            r = c["routes"][0]
            r["acceptance"] = {"diagnosis": "d.json", "stability": "s.json"}
            binding = catalog.binding(c, r, [], "batch-one", {"mihomo": "1.19.32"})
            diagnosis = {
                "completed": True,
                "routes": {
                    "test": {
                        "binding": binding,
                        "fingerprint": catalog.fingerprint(c, r),
                        "ok": True,
                        "exit_ipv4": r["expected_exit_ipv4"],
                    }
                },
            }
            stability = {
                "completed": True,
                "elapsed_seconds": 1800,
                "all_declared_passed": False,
                "bindings": {"test": binding},
                "cases": {
                    "test/a": {"checks": 60, "failures": 0},
                    "test/b": {"checks": 60, "failures": 0},
                    "other/a": {"checks": 60, "failures": 60},
                },
            }
            atomic(Path(d) / "d.json", diagnosis)
            atomic(Path(d) / "s.json", stability)
            self.assertTrue(catalog.accepted(c, r, d))
            diagnosis["completed"] = False
            atomic(Path(d) / "d.json", diagnosis)
            self.assertFalse(catalog.accepted(c, r, d))
            diagnosis["completed"] = True
            diagnosis["routes"]["test"]["binding"] = {**binding, "batch_id": "new"}
            atomic(Path(d) / "d.json", diagnosis)
            self.assertFalse(catalog.accepted(c, r, d))

    def test_rollback_cannot_revert_a_concurrent_deployment(self):
        with (
            patch.object(deploy, "environment"),
            patch.object(deploy, "locked"),
            patch.object(deploy, "state", return_value={"generation": "other"}),
            patch.object(deploy, "restore") as restore,
        ):
            with self.assertRaises(Error):
                deploy.rollback("/var/lib/vrk/backups/one.json", "mine")
            restore.assert_not_called()

    def test_public_clash_only_build_accepts_client_chains(self):
        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            c["nodes"]["carrier"] = copy.deepcopy(c["nodes"]["node"])
            c["nodes"]["node"]["dialer-proxy"] = "carrier"
            with (
                patch(
                    "vrk.subscription.locked_rule", side_effect=["+.example.cn\n", "192.0.2.0/24\n"]
                ),
                patch("vrk.subscription.run", return_value=SimpleNamespace(returncode=0)),
            ):
                build(
                    c,
                    d,
                    Path(d) / "bundle",
                    "https://sub.example.com",
                    None,
                    "/mihomo",
                    True,
                    formats="clash",
                    access_mode="public",
                )
            b = Path(d) / "bundle"
            self.assertFalse((b / "v2ray.txt").exists())
            self.assertIn("/rules/", (b / "desktop.json").read_text())
            self.assertIn("/clash/providers/builder.yaml", (b / "openwrt-example.json").read_text())

    def test_republish_does_not_destroy_previous_release(self):
        with tempfile.TemporaryDirectory() as d:
            first = bundle(d)
            second_dir = Path(d) / "second"
            second_dir.mkdir()
            c = inventory()
            c["nodes"]["node"]["port"] += 1
            second = bundle(second_dir, c)
            fixture = fixtures.PublicationTransactionTests()
            cfg = fixture.fixture(d)
            stack, _ = fixture.patches(d)
            access_file = Path(d) / "access.json"
            root = Path(cfg["root"])
            with stack:
                publish(cfg, first, access_file, True)
                first_id = read(root / "owner.json")["revision"]
                publish(cfg, second, access_file, True)
                publish(cfg, second, access_file, True)
                self.assertEqual(read(root / "owner.json")["previous"], "releases/" + first_id)
                rollback(cfg, access_file, True)
                self.assertEqual(read(root / "owner.json")["revision"], first_id)

    def test_verification_records_binding_from_actual_manifest(self):
        from vrk.verification import verify
        from test_verification import cases

        with tempfile.TemporaryDirectory() as d:
            c = inventory()
            atomic(Path(d) / "catalog.json", c)
            manifest = cases()
            manifest.update(
                rounds=1,
                interval=0,
                evidence={
                    "catalog": str(Path(d) / "catalog.json"),
                    "batch_id": "one",
                    "core_versions": {"mihomo": "1.19.32"},
                },
            )
            with patch(
                "vrk.verification.probe",
                return_value={"proxy": "test", "target": "controlled", "ok": True},
            ):
                result = verify(manifest, Path(d) / "raw.jsonl")
            self.assertEqual(
                result["bindings"]["test"],
                catalog.binding(
                    c, c["routes"][0], manifest["targets"], "one", {"mihomo": "1.19.32"}
                ),
            )

    def test_v2ray_only_needs_neither_rule_download_nor_mihomo(self):
        with (
            tempfile.TemporaryDirectory() as d,
            patch("vrk.subscription.locked_rule") as download,
            patch("vrk.subscription.run") as core,
        ):
            build(
                inventory(),
                d,
                Path(d) / "bundle",
                "https://sub.example.com",
                None,
                None,
                True,
                formats="v2ray",
                access_mode="public",
            )
            from vrk.publishing import validate_bundle

            m = validate_bundle(Path(d) / "bundle")
            self.assertEqual(set(m["artifacts"]), {"v2ray.txt"})
            self.assertEqual(set(m["formats"]), {"v2ray"})
            download.assert_not_called()
            core.assert_not_called()

    def test_rejected_candidate_never_changes_public_pointer(self):
        with tempfile.TemporaryDirectory() as d:
            first = bundle(d)
            fixture = fixtures.PublicationTransactionTests()
            cfg = fixture.fixture(d)
            stack, runner = fixture.patches(d)
            with stack:
                publish(cfg, first, Path(d) / "access.json", True)
                root = Path(cfg["root"])
                original = (root / "current").resolve()

                def reject(args, **kwargs):
                    if "-t" in args:
                        self.assertEqual((root / "current").resolve(), original)
                        return SimpleNamespace(returncode=1, stdout="", stderr="invalid")
                    return SimpleNamespace(
                        returncode=0,
                        stdout="Hostname sub.example.com does match certificate\n",
                        stderr="",
                    )

                runner.side_effect = reject
                with self.assertRaises(Error):
                    publish(cfg, first, Path(d) / "access.json", True)
                self.assertEqual((root / "current").resolve(), original)

    def test_https_failure_restores_loaded_config_and_service_state(self):
        with tempfile.TemporaryDirectory() as d:
            first = bundle(d)
            fixture = fixtures.PublicationTransactionTests()
            cfg = fixture.fixture(d)
            stack, runner = fixture.patches(d)
            with stack:
                publish(cfg, first, Path(d) / "access.json", True)
                root = Path(cfg["root"])
                original = (root / "nginx.conf").read_text()
                with patch("vrk.publishing.health", side_effect=Error("failed HTTPS")):
                    with self.assertRaises(Error):
                        publish(cfg, first, Path(d) / "access.json", True)
                self.assertEqual((root / "nginx.conf").read_text(), original)
                self.assertFalse((root / "pending.json").exists())
                self.assertTrue(
                    any(
                        call.args[0][:2] == ["systemctl", "reload-or-restart"]
                        for call in runner.call_args_list
                    )
                )

    def test_state_commit_failure_restores_running_release(self):
        with tempfile.TemporaryDirectory() as d:
            first = bundle(d)
            fixture = fixtures.PublicationTransactionTests()
            cfg = fixture.fixture(d)
            stack, runner = fixture.patches(d)
            root = Path(cfg["root"])
            with stack:
                publish(cfg, first, Path(d) / "access.json", True)
                old_owner = read(root / "owner.json")
                failed = False

                def commit_error(path, data, *args, **kwargs):
                    nonlocal failed
                    if Path(path) == root / "owner.json" and not failed:
                        failed = True
                        raise OSError("injected commit failure")
                    return atomic(path, data, *args, **kwargs)

                with patch("vrk.publishing.atomic", side_effect=commit_error):
                    with self.assertRaises(OSError):
                        publish(cfg, first, Path(d) / "access.json", True)
                self.assertEqual(read(root / "owner.json"), old_owner)
                self.assertFalse((root / "pending.json").exists())
                self.assertTrue(
                    any(
                        x.args[0][:2] == ["systemctl", "reload-or-restart"]
                        for x in runner.call_args_list
                    )
                )

    def test_public_origin_port_requires_explicit_reverse_proxy(self):
        from vrk.publishing import configuration

        with tempfile.TemporaryDirectory() as d:
            cfg = fixtures.PublicationTransactionTests().fixture(d)
            cfg["base_url"] = "https://sub.example.com"
            with self.assertRaises(Error):
                configuration(cfg, "fixture")
            cfg["reverse_proxy"] = True
            self.assertIn("18543", configuration(cfg, "fixture"))

    def test_public_rule_version_cannot_escape_release_directory(self):
        from vrk.publishing import validate_bundle

        with tempfile.TemporaryDirectory() as d:
            b = bundle(d)
            manifest = read(b / "manifest.json")
            manifest.update(access_mode="public", name="builder", rule_version="../../outside")
            atomic(b / "manifest.json", manifest)
            with self.assertRaises(Error):
                validate_bundle(b)

    def test_ssh_acceptance_uses_exact_snapshot_and_generation(self):
        import json
        from vrk.acceptance import remote_apply

        before = {
            "all_declared_passed": True,
            "cases": {"test/a": {"failures": 0}, "test/b": {"failures": 0}},
        }
        after = {
            "all_declared_passed": False,
            "cases": {"test/a": {"failures": 1}, "test/b": {"failures": 1}},
        }
        deployment = {
            "changed": True,
            "generation": "mine",
            "backup": "/var/lib/vrk/backups/mine.json",
        }
        with tempfile.TemporaryDirectory() as d:
            args = SimpleNamespace(
                verify_output=str(Path(d) / "evidence"),
                command="apply",
                host="fixture",
                jump=None,
                config="fixture.json",
                secrets=None,
                lock=None,
            )
            with (
                patch("vrk.acceptance.verify", side_effect=[before, after, before]),
                patch(
                    "vrk.acceptance.execute", side_effect=[json.dumps(deployment), "{}"]
                ) as execute,
            ):
                remote_apply(args, {"targets": [{}, {}]})
            self.assertEqual(
                execute.call_args_list[1].args[1],
                ["rollback", "--snapshot", deployment["backup"], "--expected-generation", "mine"],
            )
            self.assertEqual(read(Path(args.verify_output) / "deployment.json"), deployment)
