"""Pure offline preservation policy. No runtime or authority provider."""
import json


def _identifier(value):
    return type(value) is str and bool(value.strip())


# Closed policy for this unqualified preservation package, not a native schema.
# No external evidence is available to promote any unknown to verified.
_UNKNOWN = {"status": "UNKNOWN", "value": None, "blocker_owner": _identifier}
_PROCESS = {"role": _identifier, "enabled": False, "observed": False, "runtime": None}
_POLICY = {
    "schema_version": 1, "task_key": "CP090",
    "classification": "LEGACY_ISOLATED",
    "deployment_decision": "isolated-preservation-no-activation",
    "classification_reason": _identifier,
    "source": {
        # Supported consolidated design binding only; not legacy custody proof.
        "reference": "reference/workflows/L01.json",
        "upstream": None, "version": None, "edition": None, "digest": None,
        "architecture": None, "status": "UNKNOWN", "blocker_owner": _identifier},
    "processes": {"persistent": [dict(_PROCESS, role="Factorio/FLE native stage")],
                  "transient": [dict(_PROCESS, role="custom controller actions")],
                  "inventory_status": "UNKNOWN", "blocker_owner": _identifier},
    "dependencies": _UNKNOWN, "database_cache": _UNKNOWN,
    "identity": {"uid": None, "gid": None, "runtime_owner": None,
                 "status": "UNKNOWN", "blocker_owner": _identifier},
    "network": {"ingress": "DENY", "egress": "DENY", "rcon": "PRIVATE_DISABLED",
                "public_route": False, "enforcement": "NOT_RUN"},
    "volumes": {"paths": None, "ownership": None, "access": "UNKNOWN",
                "automatic_provisioning": False, "deletion": False,
                "blocker_owner": _identifier},
    "secret_references": _UNKNOWN,
    "health": {"liveness": "NOT_RUN", "startup": "DISABLED", "readiness": False,
               "probe": None},
    "recovery": {"migration": "FORBIDDEN", "backup_identity": None,
                 "restore": "HOLD_ONLY", "rollback": "HOLD_ONLY",
                 "reconciliation": "UNRESOLVED", "evidence": "NOT_RUN",
                 "blocker_owner": _identifier},
    "resources": {"runtime_cpu": None, "runtime_ram_mib": None,
                  "runtime_disk_mib": None, "runtime_gpu": None,
                  "enforcement": "NOT_RUN", "blocker_owner": _identifier,
                  "worker_reservation": {"cpu": 1, "memory_mib": 1536,
                                         "gpu": 0, "slots": 1, "integration": 0}},
    "redaction": {"mode": "FIXED_ENUM_ALLOWLIST", "raw_input_logging": False},
    "licenses": {
        # Existing repository attribution retained verbatim. This does not
        # attribute MIT to Factorio/FLE or any unverified runtime artifact.
        "repository": "MIT per F15 engineering decision",
        "third_party": None, "preserve_notices": True, "status": "UNKNOWN",
        "blocker_owner": _identifier},
    "sbom": _UNKNOWN, "vulnerabilities": _UNKNOWN,
    "safety": {"controller_enabled": False, "autostart": False,
               "activation_enabled": False, "outbound_state": "HOLD",
               "intent": lambda x: type(x) is str and x in ("held", "stopped", "retired"),
               "original_window": None},
    "qualification": {"native_install": "NOT_RUN", "native_recovery": "NOT_RUN",
                      "native_version": "NOT_RUN", "source_acceptance_cases": "NOT_RUN",
                      "complete": False}}


def _check(value, rule, path, errors):
    if type(rule) is dict:
        if type(value) is not dict:
            errors.append(path)
            return
        if value.keys() != rule.keys():
            errors.append(path + ".shape")
        for key in rule.keys() & value.keys():
            _check(value[key], rule[key], path + "." + key, errors)
    elif type(rule) is list:
        if type(value) is not list or not value:
            errors.append(path)
        else:
            for item in value:
                _check(item, rule[0], path + "[]", errors)
    elif callable(rule):
        if not rule(value):
            errors.append(path)
    elif type(value) is not type(rule) or value != rule:
        errors.append(path)


def _validate_manifest(m):
    errors = []
    _check(m, _POLICY, "manifest", errors)
    return sorted(set(errors))


def validate_manifest(m):
    try:
        return _validate_manifest(m)
    except (TypeError, KeyError, ValueError, AttributeError):
        return ["malformed"]

def activation_decision(request, now):
    """Evaluate synthetic prerequisites only; even a valid request stays HOLD."""
    if not isinstance(request, dict) or type(now) is not int:
        return "HOLD_INVALID"
    r = request
    if not _identifier(r.get("owner")) or not _identifier(r.get("approval")):
        return "HOLD_AUTHORITY"
    if (not _identifier(r.get("revision")) or
        not _identifier(r.get("approved_revision")) or
        r["revision"] != r["approved_revision"]):
        return "HOLD_REVISION"
    times = [r.get(k) for k in ("start", "end", "original_end")]
    if any(type(t) is not int for t in times) or not times[0] <= now < min(times[1:]):
        return "HOLD_WINDOW"
    owners = r.get("controller_owners")
    if (type(owners) is not list or len(owners) != 1 or
        not _identifier(owners[0]) or owners[0] != r["owner"]):
        return "HOLD_OWNERSHIP"
    if r.get("reconciled") is not True or r.get("restore_resolved") is not True:
        return "HOLD_RECONCILIATION"
    if r.get("storage") != "verified":
        return "HOLD_STORAGE"
    if set(r) != {"owner", "approval", "revision", "approved_revision", "start",
                  "end", "original_end", "controller_owners", "reconciled",
                  "restore_resolved", "storage"}:
        return "HOLD_INVALID"
    return "HOLD_OFFLINE_ONLY"

def recovery_plan(intent, outcome, storage):
    """No plan can start, delete, provision or replay anything."""
    retained = intent if intent in ("held", "stopped", "retired") else "held"
    return {"intent": retained, "state": "HOLD", "running": False,
            "replay": False, "delete": False, "provision": False,
            "blocker": "STORAGE" if storage != "verified" else
                       ("RECONCILIATION" if outcome != "reconciled" else "OFFLINE_ONLY")}

def record_action(action_key, seen):
    """Synthetic full contract key; in-memory deduplication is not a durable ledger."""
    if not isinstance(action_key, tuple) or len(action_key) != 5 or any(
        not isinstance(x, str) or not x for x in action_key):
        return frozenset(seen), "HOLD_INVALID"
    previous = frozenset(seen)
    if action_key in previous:
        return previous, "DUPLICATE"
    return previous | {action_key}, "HOLD"

def evidence(_untrusted):
    """Emit no user-controlled strings, keys, nested data, errors or credentials."""
    return json.dumps({"component": "CP090", "state": "HOLD", "scope": "SYNTHETIC_ONLY"},
                      sort_keys=True)
