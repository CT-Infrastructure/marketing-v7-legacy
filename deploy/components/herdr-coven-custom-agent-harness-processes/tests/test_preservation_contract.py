"""Offline regressions against the actual published CP092 JSON, not mock schemas.

Authored only; executor records independent command/revision receipts.
"""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cp092_contracts", ROOT / "preservation/validate_contracts.py")
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)

class PreservationContracts(unittest.TestCase):
    def setUp(self):
        self.documents = V.load_package(ROOT, include_fixtures=True)

    def reject(self, documents):
        with self.assertRaises((ValueError, RecursionError)):
            V.validate_documents(documents, include_fixtures=True)

    def changed(self, path, key, value):
        documents = copy.deepcopy(self.documents)
        documents[path][key] = value
        self.reject(documents)

    def test_actual_published_package(self):
        self.assertEqual(V.validate_documents(self.documents, True),
                         "STRUCTURALLY_VALID_HOLD_NOT_NATIVE_QUALIFIED")
        self.assertNotEqual(self.documents["preservation/held-state.json"]["schema"],
                            self.documents["tests/fixtures/synthetic-held.json"]["schema"])

    def test_every_actual_document_rejects_missing_extra_and_wrong_shape(self):
        for name, document in self.documents.items():
            for malformed in (None, [], "private-input", 1, True):
                with self.subTest(name=name, malformed=type(malformed).__name__):
                    data = copy.deepcopy(self.documents)
                    data[name] = malformed
                    self.reject(data)
            data = copy.deepcopy(self.documents)
            del data[name]
            self.reject(data)
            data = copy.deepcopy(self.documents)
            data[name]["unexpected"] = None
            self.reject(data)
            for key in document:
                data = copy.deepcopy(self.documents)
                del data[name][key]
                self.reject(data)

    def test_every_actual_leaf_rejects_type_and_value_mutation(self):
        # Includes nested native facts, safety flags, all pins and acceptance rows.
        stack = [((), self.documents)]
        while stack:
            path, value = stack.pop()
            if isinstance(value, dict):
                stack.extend((path + (key,), child) for key, child in value.items())
            elif isinstance(value, list):
                stack.extend((path + (index,), child) for index, child in enumerate(value))
            else:
                wrong = False if value is None else None
                altered = (not value if type(value) is bool else
                           value + 1 if type(value) in (int, float) else
                           "MUTATED" if type(value) is str else "invented")
                for replacement in (wrong, altered):
                    with self.subTest(path=path, kind=type(replacement).__name__):
                        parent = self.documents
                        for part in path[:-1]:
                            parent = parent[part]
                        original = parent[path[-1]]
                        try:
                            parent[path[-1]] = replacement
                            self.reject(self.documents)
                        finally:
                            parent[path[-1]] = original

    def test_source_identity_and_pin_mutations_are_rejected(self):
        for key in V.ROW_KEYS:
            data = copy.deepcopy(self.documents)
            data["preservation/source-map.json"]["sources"][0][key] = (
                False if key == "pin_match" else "0" * (64 if "sha256" in key else 40))
            self.reject(data)
        for collection in ("sources", "source_acceptance"):
            data = copy.deepcopy(self.documents)
            data["preservation/source-map.json"][collection].reverse()
            self.reject(data)
            data = copy.deepcopy(self.documents)
            data["preservation/source-map.json"][collection][1] = copy.deepcopy(
                data["preservation/source-map.json"][collection][0])
            self.reject(data)

    def test_all_source_and_native_cases_stay_not_run_without_evidence(self):
        cases = self.documents["preservation/source-map.json"]["source_acceptance"]
        self.assertEqual(len(cases), 576)
        for collection, key in (("preservation/source-map.json", "source_acceptance"),
                                ("component.json", "native_acceptance")):
            for status in ("PASS", "UNKNOWN", "ACCEPTED", None, True):
                data = copy.deepcopy(self.documents)
                data[collection][key][0]["status"] = status
                self.reject(data)
            data = copy.deepcopy(self.documents)
            data[collection][key][0]["evidence_ref"] = "invented-proof"
            self.reject(data)

    def test_unknown_ownership_and_native_facts_cannot_be_invented(self):
        for field in ("current_owner_ref", "controller_ref", "session_ref", "generation",
                      "revision", "original_cutoff", "evidence_ref"):
            self.changed("preservation/ownership.json", field, "invented")
        for fact in self.documents["component.json"]["native_facts"]:
            data = copy.deepcopy(self.documents)
            data["component.json"]["native_facts"][fact]["value"] = "guessed"
            self.reject(data)
            data = copy.deepcopy(self.documents)
            del data["component.json"]["native_facts"][fact]["owner_role"]
            self.reject(data)
        # Required native logging policy stays explicitly unresolved, with no
        # invented policy, custodian, source or evidence, and no omitted record.
        log_redaction = self.documents["component.json"]["native_facts"]["log_redaction"]
        self.assertEqual(log_redaction, {
            "status": "UNKNOWN", "value": None,
            "owner_role": "Legacy workload owner", "source_id": "SRC-002",
            "evidence_ref": None,
        })
        self.assertEqual(V.validate_documents(self.documents, True),
                         "STRUCTURALLY_VALID_HOLD_NOT_NATIVE_QUALIFIED")
        data = copy.deepcopy(self.documents)
        del data["component.json"]["native_facts"]["log_redaction"]
        self.reject(data)
        for field in log_redaction:
            with self.subTest(log_redaction_missing=field):
                data = copy.deepcopy(self.documents)
                del data["component.json"]["native_facts"]["log_redaction"][field]
                self.reject(data)
        for field, value in (("status", "VERIFIED"), ("value", "invented-policy"),
                             ("owner_role", "invented-owner"), ("source_id", "SRC-001"),
                             ("evidence_ref", "invented-proof")):
            with self.subTest(log_redaction_altered=field):
                data = copy.deepcopy(self.documents)
                data["component.json"]["native_facts"]["log_redaction"][field] = value
                self.reject(data)

    def test_no_activation_or_resource_reservation(self):
        self.changed("component.json", "production_authorized", True)
        self.changed("component.json", "auto_activation", True)
        self.changed("component.json", "production_gate", "OPEN")
        for key in self.documents["component.json"]["resources"]:
            for value in (1, False, -1, 0.0):
                data = copy.deepcopy(self.documents)
                data["component.json"]["resources"][key] = value
                self.reject(data)
        for key in ("auto_start", "auto_migrate", "auto_delete", "attach_marketing_credentials",
                    "backup_verified", "restore_verified", "replay_authorized"):
            self.changed("preservation/held-state.json", key, True)
        for value in ("READY", "RUNNING", "STOPPED", None):
            self.changed("preservation/held-state.json", "restore_target", value)
        self.changed("preservation/held-state.json", "uncertain_effect_policy", "RETRY")

    def test_all_private_locator_forms_and_payloads_rejected(self):
        locators = ["/home/private", "C:\\Users\\private", "\\\\host\\share", "../private",
                    "~/private", "file:///private", "https://private.invalid/session",
                    "s3://private/key", "ssh://private", "data:text/plain,private",
                    "opaque:cp092:../private", "opaque:cp092:" + "A" * 32,
                    "opaque:cp092:" + "a" * 31, "opaque:cp092:" + "a" * 33,
                    "opaque:cp092:" + "a" * 32 + "\n", "private=payload"]
        for locator in locators:
            fixture = copy.deepcopy(self.documents["tests/fixtures/synthetic-private-reference.json"])
            fixture["reference_id"] = locator
            with self.assertRaises(ValueError):
                V.validate_private_reference(fixture)
            self.changed("preservation/private-artifact-contract.json", "references", [locator])
        self.changed("preservation/private-artifact-contract.json", "public_locators_allowed", True)
        self.changed("preservation/private-artifact-contract.json", "private_contents_allowed", True)
        fixture = copy.deepcopy(self.documents["tests/fixtures/synthetic-private-reference.json"])
        fixture["value"] = "private-payload"
        with self.assertRaises(ValueError):
            V.validate_private_reference(fixture)

    def test_bounded_json_duplicate_nonfinite_encoding_depth(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{',
                    b'\xff', b'\xef\xbb\xbf{}', '{}'.encode('utf-16'),
                    b'x' * (V.MAX_BYTES + 1), b'[' * 10000 + b']' * 10000):
            with self.subTest(length=len(raw)):
                with self.assertRaises((ValueError, RecursionError)):
                    V.decode(raw)
        with self.assertRaises(ValueError):
            V.decode(json.dumps([0] * (V.MAX_NODES + 1)).encode())

    def test_real_cli_codes_redaction_and_deep_json(self):
        script = ROOT / "preservation/validate_contracts.py"
        for extra, expected in (([], 0), (["--include-fixtures"], 0),
                                (["--require-native-ready"], 2)):
            result = subprocess.run([sys.executable, "-B", str(script), str(ROOT)] + extra,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")
        sentinel = "DO_NOT_ECHO_PRIVATE_SENTINEL"
        with tempfile.TemporaryDirectory(prefix="cp092-offline-") as tmp:
            target = Path(tmp)
            for name, document in self.documents.items():
                path = target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(document), encoding="utf-8")
            victim = target / "component.json"
            for payload in (sentinel.encode(), b'[' * 10000 + b']' * 10000,
                            ('{"' + sentinel + '":NaN}').encode(), b'x' * (V.MAX_BYTES + 1)):
                victim.write_bytes(payload)
                result = subprocess.run([sys.executable, "-B", str(script), str(target)],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "")
                self.assertNotIn(sentinel, result.stdout)
                self.assertNotIn(str(target), result.stdout)
                self.assertLess(len(result.stdout), 120)

    def test_regular_file_containment(self):
        with tempfile.TemporaryDirectory(prefix="cp092-links-") as tmp:
            root = Path(tmp)
            outside = root / "outside.json"
            outside.write_text('{}', encoding='utf-8')
            package = root / "package"
            package.mkdir()
            try:
                (package / "linked.json").symlink_to(outside)
            except OSError as error:
                self.skipTest("Symlink unavailable; mandatory Linux execution: " + type(error).__name__)
            with self.assertRaises(ValueError):
                V.read_regular(package, "linked.json")
            with self.assertRaises(ValueError):
                V.read_regular(package, "../outside.json")

if __name__ == "__main__":
    unittest.main()
