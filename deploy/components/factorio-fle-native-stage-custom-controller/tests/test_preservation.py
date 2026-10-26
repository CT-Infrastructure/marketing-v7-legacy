"""Synthetic offline tests; no native/runtime qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("preservation", ROOT / "preservation.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ROOT / "component.json").read_text(encoding="utf-8"))
        self.request = dict(owner="synthetic-owner", approval="synthetic-decision",
            revision="synthetic-rev", approved_revision="synthetic-rev",
            start=100, end=300, original_end=250,
            controller_owners=["synthetic-owner"], reconciled=True,
            restore_resolved=True, storage="verified")

    def test_manifest(self):
        self.assertEqual(p.validate_manifest(self.manifest), [])
        self.assertFalse(self.manifest["qualification"]["complete"])

    def test_missing_categories_and_nested_fields(self):
        for category, value in self.manifest.items():
            if isinstance(value, dict):
                m = copy.deepcopy(self.manifest)
                del m[category]
                with self.subTest(category=category):
                    self.assertTrue(p.validate_manifest(m))
                for field in value:
                    m = copy.deepcopy(self.manifest)
                    del m[category][field]
                    # worker_reservation is metadata rather than a native safety gate.
                    if field == "worker_reservation":
                        continue
                    with self.subTest(category=category, field=field):
                        self.assertTrue(p.validate_manifest(m))

    def test_malformed(self):
        for value in (None, [], "bad", 2, {}, {"source": []}):
            self.assertTrue(p.validate_manifest(value))
        with self.assertRaises(json.JSONDecodeError):
            json.loads("{invalid")

    def test_malformed_nested_values(self):
        for category, field, value in (
            ("processes", "persistent", None),
            ("safety", "intent", []),
            ("source", "digest", "invented"),
            ("source", "status", "VERIFIED"),
            ("identity", "runtime_owner", "invented"),
            ("volumes", "paths", "/invented")):
            m = copy.deepcopy(self.manifest)
            m[category][field] = value
            self.assertTrue(p.validate_manifest(m))

    def test_contradictory_claims(self):
        mutations = [
            ("safety", "activation_enabled", True), ("safety", "autostart", True),
            ("safety", "controller_enabled", True), ("safety", "outbound_state", "READY"),
            ("safety", "intent", "running"), ("network", "rcon", "PUBLIC"),
            ("network", "ingress", "ALLOW"), ("network", "egress", "ALLOW"),
            ("network", "public_route", True), ("volumes", "deletion", True),
            ("volumes", "automatic_provisioning", True), ("health", "readiness", True),
            ("health", "startup", "ENABLED"), ("recovery", "restore", "START"),
            ("recovery", "rollback", "START"), ("recovery", "migration", "AUTO"),
            ("qualification", "complete", True), ("qualification", "native_install", "PASS"),
            ("qualification", "native_recovery", "PASS"),
            ("qualification", "native_version", "PASS"),
            ("qualification", "source_acceptance_cases", "PASS"),
            ("redaction", "raw_input_logging", True)]
        for category, key, value in mutations:
            m = copy.deepcopy(self.manifest)
            m[category][key] = value
            with self.subTest(category=category, key=key):
                self.assertTrue(p.validate_manifest(m))
        for kind in ("persistent", "transient"):
            m = copy.deepcopy(self.manifest)
            m["processes"][kind][0]["enabled"] = True
            self.assertTrue(p.validate_manifest(m))

    def test_unknown_cannot_claim_verified(self):
        for category in ("dependencies", "database_cache", "secret_references", "sbom", "vulnerabilities"):
            m = copy.deepcopy(self.manifest)
            m[category]["value"] = "invented"
            self.assertTrue(p.validate_manifest(m))

    def test_each_authority_gate(self):
        cases = {
            "owner": (None, "HOLD_AUTHORITY"), "approval": (None, "HOLD_AUTHORITY"),
            "revision": ("wrong", "HOLD_REVISION"),
            "approved_revision": (None, "HOLD_REVISION"),
            "start": (None, "HOLD_WINDOW"), "end": (None, "HOLD_WINDOW"),
            "original_end": (None, "HOLD_WINDOW"),
            "controller_owners": (["synthetic-owner", "duplicate"], "HOLD_OWNERSHIP"),
            "reconciled": (False, "HOLD_RECONCILIATION"),
            "restore_resolved": (False, "HOLD_RECONCILIATION"),
            "storage": ("inaccessible", "HOLD_STORAGE")}
        for key, (value, expected) in cases.items():
            request = dict(self.request, **{key: value})
            with self.subTest(key=key):
                self.assertEqual(p.activation_decision(request, 150), expected)
        for now in (99, 250, 300):
            self.assertEqual(p.activation_decision(self.request, now), "HOLD_WINDOW")
        self.assertEqual(p.activation_decision(dict(self.request, end=999), 251), "HOLD_WINDOW")
        self.assertEqual(p.activation_decision(self.request, 150), "HOLD_OFFLINE_ONLY")
        self.assertEqual(p.activation_decision(None, 150), "HOLD_INVALID")

    def test_restore_restart_preserve_intent(self):
        for intent in ("held", "stopped", "retired"):
            for storage in ("verified", "unknown", "inaccessible"):
                for outcome in ("unknown", "timeout", "reconciled"):
                    plan = p.recovery_plan(intent, outcome, storage)
                    self.assertEqual(plan["intent"], intent)
                    self.assertEqual(plan["state"], "HOLD")
                    for key in ("running", "replay", "delete", "provision"):
                        self.assertFalse(plan[key])
                    if storage != "verified":
                        self.assertEqual(plan["blocker"], "STORAGE")
                    elif outcome != "reconciled":
                        self.assertEqual(plan["blocker"], "RECONCILIATION")

    def test_action_deduplication_scope(self):
        key = ("synthetic-client", "synthetic-source", "event-1", "controller", "rev-1")
        seen, state = p.record_action(key, frozenset())
        self.assertEqual(state, "HOLD")
        again, state = p.record_action(key, seen)
        self.assertEqual(state, "DUPLICATE")
        self.assertEqual(again, seen)
        self.assertEqual(len(again), 1)
        other, state = p.record_action(key[:-1] + ("rev-2",), again)
        self.assertEqual(len(other), 2)
        self.assertEqual(state, "HOLD")
        self.assertEqual(p.record_action(("short",), seen)[1], "HOLD_INVALID")

    def test_evidence_discards_credentials_at_every_depth(self):
        marker = "SYNTHETIC_SECRET_NEVER_EMIT"
        data = {"password": marker, "token": marker, "api_key": marker,
                "nested": [{"Authorization": marker}], "state": marker,
                marker: "credential-shaped", "exception": marker}
        output = p.evidence(data)
        self.assertNotIn(marker, output)
        for key in ("password", "token", "api_key", "Authorization", "exception"):
            self.assertNotIn(key, output)
        self.assertEqual(json.loads(output)["state"], "HOLD")

    def test_classification_has_no_deployment_artifacts(self):
        self.assertTrue(self.manifest["classification_reason"].strip())
        for pattern in ("*Containerfile*", "*.container", "*.service", "*.timer"):
            self.assertEqual(list(ROOT.glob(pattern)), [])
        m = copy.deepcopy(self.manifest)
        m["classification_reason"] = ""
        self.assertTrue(p.validate_manifest(m))

if __name__ == "__main__":
    unittest.main()
