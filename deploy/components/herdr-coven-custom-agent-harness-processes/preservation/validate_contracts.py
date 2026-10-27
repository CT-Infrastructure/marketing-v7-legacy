"""Strict immutable CP092 offline contracts; no native discovery or activation.

This baseline deliberately rejects resolved native facts. Changes require a new
reviewed revision. Exit 0 is structural preservation only; readiness returns 2.
"""
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

MAX_BYTES = 2_000_000
MAX_DEPTH = 32
MAX_NODES = 50000

class ContractError(ValueError):
    """Redacted contract failure: never include caller data."""

def require(condition):
    if not condition:
        raise ContractError("CP092_INVALID")

def same(expected, actual):
    require(type(expected) is type(actual))
    if isinstance(expected, dict):
        require(expected.keys() == actual.keys())
        for key in expected:
            same(expected[key], actual[key])
    elif isinstance(expected, list):
        require(len(expected) == len(actual))
        for left, right in zip(expected, actual):
            same(left, right)
    else:
        require(expected == actual)

def bounded(value):
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        require(depth <= MAX_DEPTH and nodes <= MAX_NODES)
        require(type(item) in (dict, list, str, int, float, bool, type(None)))
        if isinstance(item, dict):
            require(all(type(k) is str for k in item))
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            require(len(item) <= 4096)

def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value

def reject_constant(_):
    raise ContractError("CP092_INVALID")

def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES)
    require(not raw.startswith(b"\xef\xbb\xbf"))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=reject_constant)
        bounded(value)
        return value
    except (ValueError, RecursionError, UnicodeError):
        raise ContractError("CP092_INVALID") from None

# Exact published UNKNOWN/HOLD schemas, including fixture schemas deliberately
# distinct from native contracts. No user-supplied schema or approval is read.
BASELINES = json.loads(r'''{
  "component.json": {
    "schema": "cp092.component.v1",
    "component_id": "CP092",
    "name": "Herdr; Coven; custom agent/harness processes",
    "function": "Historical coding sessions",
    "classification": "LEGACY_ISOLATED",
    "deployment_decision": "isolated-preservation-no-activation",
    "package_role": "OFFLINE_PRESERVATION_CONTRACT",
    "hard_prerequisites": [
      "F01",
      "F15"
    ],
    "interfaces": [
      "L01",
      "L02",
      "L03",
      "L04",
      "L05",
      "L06",
      "L07",
      "L08"
    ],
    "production_authorized": false,
    "production_gate": "G02_HOLD",
    "auto_activation": false,
    "network": {
      "ingress": "DENY",
      "egress": "DENY",
      "secret_references": []
    },
    "resources": {
      "cpu": 0,
      "memory_mib": 0,
      "disk_mib": 0,
      "gpu": 0,
      "pids": 0,
      "integration": 0,
      "slots": 0
    },
    "native_facts": {
      "version": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "edition": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "source": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "digest": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "architecture": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "runtime_dependencies": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "database": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "cache": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "uid": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "gid": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "persistent_processes": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "transient_processes": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "volumes": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "data_ownership": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "health": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "startup": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "readiness": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "migration": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "backup": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "restore": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "rollback": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "log_redaction": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "license": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "sbom": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "vulnerabilities": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      },
      "native_resource_limits": {
        "status": "UNKNOWN",
        "value": null,
        "owner_role": "Legacy workload owner",
        "source_id": "SRC-002",
        "evidence_ref": null
      }
    },
    "native_acceptance": [
      {
        "id": "CP092-AC01",
        "status": "NOT_RUN",
        "evidence_ref": null
      },
      {
        "id": "CP092-AC02",
        "status": "NOT_RUN",
        "evidence_ref": null
      },
      {
        "id": "CP092-AC03",
        "status": "NOT_RUN",
        "evidence_ref": null
      },
      {
        "id": "CP092-AC04",
        "status": "NOT_RUN",
        "evidence_ref": null
      },
      {
        "id": "CP092-AC05",
        "status": "NOT_RUN",
        "evidence_ref": null
      },
      {
        "id": "CP092-AC06",
        "status": "NOT_RUN",
        "evidence_ref": null
      }
    ]
  },
  "preservation/ownership.json": {
    "schema": "cp092.ownership.v1",
    "status": "UNKNOWN",
    "unblock_owner_role": "Legacy workload owner",
    "current_owner_ref": null,
    "controller_ref": null,
    "session_ref": null,
    "generation": null,
    "revision": null,
    "original_cutoff": null,
    "evidence_ref": null,
    "inference_from_process_name": false,
    "single_controller_required": true,
    "lock_transfer": "FORBIDDEN_WITHOUT_RECONCILIATION",
    "preserve_uncommitted_work": true,
    "preserve_locks": true,
    "preserve_failure_history": true
  },
  "preservation/held-state.json": {
    "schema": "cp092.held-state.v1",
    "record_kind": "UNRESOLVED_NATIVE_INVENTORY",
    "native_status": "UNKNOWN",
    "preservation_status": "HOLD",
    "allowed_native_states": [
      "UNKNOWN",
      "HELD",
      "STOPPED",
      "RETIRED"
    ],
    "restore_target": "HOLD",
    "auto_start": false,
    "auto_migrate": false,
    "auto_delete": false,
    "attach_marketing_credentials": false,
    "pending_actions": null,
    "pending_receipts": null,
    "effect_status": "UNKNOWN",
    "uncertain_effect_policy": "HOLD_NO_RETRY",
    "ownership_contract": "ownership.json",
    "private_reference_ids": [],
    "backup_verified": false,
    "restore_verified": false,
    "replay_authorized": false
  },
  "preservation/compatibility.json": {
    "schema": "cp092.compatibility.v1",
    "status": "UNKNOWN",
    "native_installation": "BLOCKED",
    "containerization": "NOT_APPLICABLE_OFFLINE_CONTRACT",
    "quadlet": "NOT_RENDERED",
    "supported_runtime": null,
    "supported_database": null,
    "supported_cache": null,
    "source_id": "SRC-002",
    "owner_role": "Platform owner",
    "evidence_ref": null,
    "activation_requires_separate_scope": true,
    "prerequisite_acceptance": "CONTROLLER_VERIFIED_NOT_AUTHOR_PROVEN",
    "cp090_required": false,
    "cp091_required": false
  },
  "preservation/private-artifact-contract.json": {
    "schema": "cp092.private-artifact-contract.v1",
    "status": "HOLD",
    "reference_format": "opaque:cp092:<32 lowercase hex>",
    "allowed_kinds": [
      "worktree",
      "session-database",
      "pending-actions",
      "receipt-ledger",
      "lock-record",
      "failure-history",
      "credential-custody"
    ],
    "references": [],
    "public_locators_allowed": false,
    "private_contents_allowed": false,
    "credential_values_allowed": false,
    "custody_owner_role": "Authorized private custodian",
    "locator_resolution": "SEPARATE_AUTHORIZED_PRIVATE_WORKFLOW",
    "encryption_key_ref": null,
    "rights_verified": false,
    "restore_verified": false
  },
  "tests/fixtures/synthetic-held.json": {
    "schema": "cp092.synthetic-held.v1",
    "synthetic": true,
    "session_ref": "synthetic-session",
    "current_owner_ref": "synthetic-owner",
    "controller_ref": "synthetic-controller",
    "generation": 1,
    "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "original_cutoff": 1000,
    "native_status": "STOPPED",
    "restore_target": "HOLD",
    "pending_actions": [
      "synthetic-action"
    ],
    "pending_receipts": [
      "synthetic-receipt"
    ],
    "effect_status": "UNKNOWN",
    "replay_authorized": false
  },
  "tests/fixtures/synthetic-private-reference.json": {
    "schema": "cp092.synthetic-private-reference.v1",
    "synthetic": true,
    "reference_id": "opaque:cp092:00000000000000000000000000000001",
    "kind": "session-database",
    "status": "HOLD",
    "value": null
  }
}
''')
PIN_FINGERPRINT = 'cfe178dbca73449853f79b59bfa220c4d30b46b00d73d6a7bad587b7709d0bac'
ACCEPTANCE_FINGERPRINT = 'e9d0f1c2932a269099cefc56ef9f4e7a774b49ed88ef1d9b6ab0ac7c8f4281a5'

SOURCE_HEADER = json.loads(r'''
{
  "schema": "cp092.source-map.v1",
  "authority": "READ_ONLY_SOURCE_CUSTODY_ONLY",
  "control_revision": "b2af9d5e752767a90a095e4f6f440cd7aa85286f",
  "legacy_revision": "d05862ddc91a8108dd4b4359b1180c6c0656f2fc",
  "hard_prerequisites": [
    "F01",
    "F15"
  ],
  "source_count": 503,
  "source_acceptance_count": 576,
  "raw_legacy_verified": false,
  "native_qualification": "NOT_RUN",
  "materialization_context": {
    "source_id": "SRC-503",
    "path": ".github/workflows/package-validation.yml",
    "status": "LOCKED_SOURCE_AND_CURRENT_BASE_DISTINCT_VERIFIED_BYTES",
    "appendix_sha256": "b378b3441a0b7a8b01aade15b903442c298976d63e2c7c7c8c3cd7dce4c096ef",
    "locked": {
      "revision": "d05862ddc91a8108dd4b4359b1180c6c0656f2fc",
      "git_blob_oid": "4a3ce1ecb91a38963294e5bf72db55f6c4a52c28",
      "bytes": 559,
      "sha256": "28d08eea21414316702936e66def48e4f0004c685f101bf9d482d5a0551c61d1"
    },
    "current_base": {
      "revision": "8a76526c018050fa22657b039f92198152354c5b",
      "git_blob_oid": "e53e829e57384872ac0421413d15ee90d51d454b",
      "bytes": 1130,
      "sha256": "52d4b329396b067cec2bd0000daba1b4076438e9372e38da3bfbba64ecae9731"
    },
    "source_pin_waiver": false,
    "independent_author_git_verification": false,
    "root_reported_ancestry": true
  }
}
''')
ROW_KEYS = ("source_id", "group", "path", "revision", "git_blob_oid",
            "sha256", "sha256_lf", "pin_match")

def source_map(value):
    require(type(value) is dict)
    require(value.keys() == SOURCE_HEADER.keys() | {"sources", "source_acceptance"})
    for key, expected in SOURCE_HEADER.items():
        same(expected, value[key])
    rows = value["sources"]
    require(type(rows) is list and len(rows) == 503)
    lines = []
    identities = set()
    for index, row in enumerate(rows, 1):
        require(type(row) is dict and row.keys() == set(ROW_KEYS))
        require(all(type(row[key]) is str for key in ROW_KEYS[:-1]))
        require(type(row["pin_match"]) is bool and row["pin_match"])
        require(row["source_id"] == "SRC-%03d" % index)
        require(row["group"] in ("control-public", "accepted-F01", "accepted-F15", "legacy-base"))
        path = row["path"]
        require(not path.startswith(("/", "\\")) and "\\" not in path)
        require(all(part not in ("", ".", "..") for part in path.split("/")))
        require(":" not in path and "|" not in path and "\n" not in path)
        identity = (row["group"], path)
        require(identity not in identities)
        identities.add(identity)
        for key, size in (("revision", 40), ("git_blob_oid", 40), ("sha256", 64), ("sha256_lf", 64)):
            require(re.fullmatch("[a-f0-9]{%d}" % size, row[key]) is not None)
        lines.append("|".join([row[k] for k in ROW_KEYS[:-1]] + ["true"]))
    digest = hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()
    require(digest == PIN_FINGERPRINT)
    cases = value["source_acceptance"]
    require(type(cases) is list and len(cases) == 576)
    ids = []
    for case in cases:
        require(type(case) is dict and case.keys() == {"source_test_id", "status", "evidence_ref"})
        require(type(case["source_test_id"]) is str)
        require(re.fullmatch(r"(?:[A-Z][0-9]{2}-T[0-9]{2}|BASE-[0-9]{3}|B[0-9]{2})", case["source_test_id"]) is not None)
        require(type(case["status"]) is str and case["status"] == "NOT_RUN")
        require(case["evidence_ref"] is None)
        ids.append(case["source_test_id"])
    require(len(set(ids)) == 576)
    require(hashlib.sha256(("\n".join(ids) + "\n").encode("utf-8")).hexdigest() == ACCEPTANCE_FINGERPRINT)

def validate_private_reference(value):
    """Only a synthetic, opaque reference; never a locator or private payload."""
    same(BASELINES["tests/fixtures/synthetic-private-reference.json"], value)
    require(re.fullmatch(r"opaque:cp092:[a-f0-9]{32}", value["reference_id"]) is not None)

def validate_documents(documents, include_fixtures=False):
    bounded(documents)
    required = {p for p in BASELINES if not p.startswith("tests/")}
    if include_fixtures:
        required |= {p for p in BASELINES if p.startswith("tests/")}
    required.add("preservation/source-map.json")
    require(type(documents) is dict and documents.keys() == required)
    for name in required:
        if name == "preservation/source-map.json":
            source_map(documents[name])
        else:
            same(BASELINES[name], documents[name])
    if include_fixtures:
        validate_private_reference(documents["tests/fixtures/synthetic-private-reference.json"])
    return "STRUCTURALLY_VALID_HOLD_NOT_NATIVE_QUALIFIED"

def read_regular(root, relative):
    # Stable isolated snapshots only: this is not a concurrent hostile FS service.
    # Reject links/junctions in every ancestor; do not follow a private locator.
    require(type(relative) is str and not Path(relative).is_absolute())
    require(all(part not in ('', '.', '..') for part in relative.replace(chr(92), '/').split('/')))
    path = root / relative
    require(path.is_relative_to(root))
    for parent in (path,) + tuple(path.parents):
        require(not parent.is_symlink())
        if hasattr(parent, "is_junction"):
            require(not parent.is_junction())
        require(not (getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_BYTES)
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    return decode(raw)

def load_package(root, include_fixtures=False):
    root = Path(root).absolute()
    names = [p for p in BASELINES if include_fixtures or not p.startswith("tests/")]
    names.append("preservation/source-map.json")
    return {name: read_regular(root, name) for name in names}

def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    ready = "--require-native-ready" in args
    fixtures = "--include-fixtures" in args
    args = [a for a in args if a not in ("--require-native-ready", "--include-fixtures")]
    try:
        require(len(args) == 1 and not args[0].startswith("--"))
        documents = load_package(args[0], fixtures)
        validate_documents(documents, fixtures)
    except (OSError, ValueError, RecursionError, UnicodeError, TypeError, KeyError, OverflowError):
        print("CP092_INVALID: bounded offline contract rejected")
        return 1
    if ready:
        print("CP092_BLOCKED: native evidence UNKNOWN; G02 HOLD; all native AC NOT_RUN")
        return 2
    print("CP092_VALID: structural HOLD only; no native qualification or activation")
    return 0

if __name__ == "__main__":
    sys.exit(main())
