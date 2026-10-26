"""Regression tests for closed offline policy and typed synthetic authority."""
import copy
import unittest
from test_preservation import p, ROOT
import json


class StrictPolicyTests(unittest.TestCase):
    def setUp(self):
        self.m = json.loads((ROOT / "component.json").read_text())
        self.r = dict(owner="owner", approval="approval", revision="rev",
                      approved_revision="rev", start=10, end=90, original_end=80,
                      controller_owners=["owner"], reconciled=True,
                      restore_resolved=True, storage="verified")

    def test_every_shape_closed_and_required(self):
        def walk(node, path=()):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield path, key, value
                    yield from walk(value, path + (key,))
            elif isinstance(node, list):
                for i, value in enumerate(node):
                    yield from walk(value, path + (i,))
        for path, key, value in walk(self.m):
            for operation in ("remove", "extra", "type"):
                m = copy.deepcopy(self.m)
                node = m
                for part in path:
                    node = node[part]
                if operation == "remove":
                    del node[key]
                elif operation == "extra":
                    node["production_authorized"] = True
                else:
                    node[key] = [] if not isinstance(value, list) else {}
                with self.subTest(path=path, key=key, operation=operation):
                    self.assertTrue(p.validate_manifest(m))

    def test_all_unknowns_and_evidence_stay_unqualified(self):
        for category, fields in self.m.items():
            if not isinstance(fields, dict):
                continue
            for key, value in fields.items():
                if value is None or key in ("status", "inventory_status", "enforcement",
                                             "liveness", "evidence"):
                    for replacement in ("VERIFIED", "PASS", True, 1, [], {}):
                        m = copy.deepcopy(self.m)
                        m[category][key] = replacement
                        with self.subTest(category=category, key=key, replacement=replacement):
                            self.assertTrue(p.validate_manifest(m))

    def test_identity_types_and_blank_strings(self):
        for bad in (None, True, 1, [], ["x"], {}, {"x": 1}, "", " \t\n"):
            for key in ("owner", "approval", "revision", "approved_revision"):
                r = copy.deepcopy(self.r)
                r[key] = bad
                if key == "owner":
                    r["controller_owners"] = [bad]
                if key == "revision":
                    r["approved_revision"] = bad
                with self.subTest(key=key, bad=bad):
                    expected = "HOLD_AUTHORITY" if key in ("owner", "approval") else "HOLD_REVISION"
                    self.assertEqual(p.activation_decision(r, 20), expected)
            for category, fields in self.m.items():
                if isinstance(fields, dict) and "blocker_owner" in fields:
                    m = copy.deepcopy(self.m)
                    m[category]["blocker_owner"] = bad
                    self.assertTrue(p.validate_manifest(m))

    def test_exact_single_typed_controller_owner(self):
        for owners in (None, "owner", ("owner",), [], [True], ["owner", "owner"],
                       [" owner"], ["OWNER"], [{"owner": "owner"}]):
            self.assertEqual(p.activation_decision(dict(self.r, controller_owners=owners), 20),
                             "HOLD_OWNERSHIP")
        self.assertEqual(p.activation_decision(self.r, 20), "HOLD_OFFLINE_ONLY")

    def test_source_attribution_and_process_contradictions(self):
        for category, key, value in (
            ("source", "reference", "reference/workflows/L02.json"),
            ("source", "reference", "reference/workflows/../workflows/L01.json"),
            ("licenses", "repository", "invented"),
            ("licenses", "third_party", "MIT"),
            ("licenses", "preserve_notices", False),
            ("volumes", "ownership", "invented"),
            ("safety", "original_window", {"end": 999})):
            m = copy.deepcopy(self.m)
            m[category][key] = value
            self.assertTrue(p.validate_manifest(m))
        for kind in ("persistent", "transient"):
            for key, value in (("autostart", True), ("observed", True),
                               ("runtime", "invented"), ("role", " "), ("role", "unverified service")):
                m = copy.deepcopy(self.m)
                m["processes"][kind][0][key] = value
                self.assertTrue(p.validate_manifest(m))
        for key in ("authorized", "production_authorized", "qualification", "approval_ref"):
            self.assertEqual(p.activation_decision(dict(self.r, **{key: True}), 20), "HOLD_INVALID")

    def test_safe_nonrunning_intents_remain_valid(self):
        for intent in ("held", "stopped", "retired"):
            m = copy.deepcopy(self.m)
            m["safety"]["intent"] = intent
            self.assertEqual(p.validate_manifest(m), [])
            self.assertFalse(m["qualification"]["complete"])
