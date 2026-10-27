"""Strict offline validation of CP091's public preservation package.

No native inventory, network, process control, deployment or acceptance authority.
UNKNOWN/null is supported; changing the evidence model requires reviewed schemas.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

FILES = (
    'component.json', 'preservation/compatibility.json',
    'preservation/held-state.json', 'preservation/ownership.json',
    'preservation/private-artifact-contract.json', 'preservation/source-map.json',
    'tests/fixtures/synthetic-held.json',
    'tests/fixtures/synthetic-private-reference.json',
)
FACTS = ('obs_version', 'edition', 'upstream_source', 'artifact_digest',
         'os_version', 'architecture', 'qt_abi', 'ffmpeg_abi', 'plugin_versions',
         'gpu_model', 'driver_version', 'encoder', 'srt_version', 'license',
         'sbom', 'vulnerability_evidence')
EFFECTS = ('autostart', 'capture', 'broadcast', 'recording', 'device_attach',
           'network', 'restore_activation', 'migration', 'delete')
REFERENCE_FIELDS = ('id', 'custodian', 'source', 'version', 'sha256', 'evidence',
                    'rights', 'retention', 'restore')
INTENTS = ('UNKNOWN', 'HELD', 'STOPPED', 'RETIRED')
OWNERS = ('Platform owner and OBS custodian', 'Legacy custodian',
          'Rights/privacy owner', 'Backup owner',
          'Legacy custodian and trusted controller',
          'Legacy custodian and rights/privacy owner')
SOURCE_ROWS_SHA256 = '8c4e43246c933276aa71be42997ed270ef51bb1c72291c18b66eab843e6996e6'
SOURCE_IDS_SHA256 = 'c2cee3ae3c6f70d583069f762533708da31a3922f540a5115ba05a707e914236'
PUBLIC_LOCK_SHA256 = '85b5161aad4db0e013f9010d5b6efaeb0059e151e7972101f8457cd840f63103'
BASE_REVISION = 'd05862ddc91a8108dd4b4359b1180c6c0656f2fc'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(expected):
    def check(value):
        require(type(value) is type(expected) and value == expected,
                'expected typed ' + repr(expected))
    return check


def choice(values):
    def check(value):
        require(type(value) is str and value in values, 'invalid enum')
    return check


def shape(value, fields):
    require(type(value) is dict and set(value) == set(fields), 'exact keys required')
    for key, validator in fields.items():
        try:
            if type(validator) is dict:
                shape(value[key], validator)
            else:
                validator(value[key])
        except ValueError as exc:
            raise ValueError(key + ': ' + str(exc)) from exc


def array(item, count=None):
    def check(value):
        require(type(value) is list, 'array required')
        require(count is None or len(value) == count, 'wrong array length')
        for entry in value:
            item(entry)
    return check


def pattern(expression):
    def check(value):
        require(type(value) is str and re.fullmatch(expression, value) is not None,
                'malformed public value')
    return check


HEX64 = pattern(r'[a-f0-9]{64}')
HEX40 = pattern(r'[a-f0-9]{40}')


def opaque(value):
    pattern(r'opaque:[a-z0-9]+(?:-[a-z0-9]+)*')(value)
    require(not any(word in value for word in
                    ('secret', 'token', 'password', 'credential', 'private-key')),
            'secret-like reference forbidden')


def label(value):
    pattern(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')(value)
    require(not any(word in value.lower() for word in
                    ('secret', 'token', 'password', 'credential', 'private-key')),
            'secret-like label forbidden')


# These six statements are reviewed public explanatory text, not inventory.
# Each field uses its own exact value. Future editorial changes require review;
# accepting arbitrary prose would reopen private locator disclosure.
PUBLIC_TEXT = {
    'db_note': 'Not inferred absent.',
    'resource_note': 'Engineering reservation only; native runtime limits UNKNOWN.',
    'log_redaction': 'Opaque references and bounded synthetic results only; no native logs or config dumps.',
    'ownership_note': 'Owner roles identify who must supply evidence; they are not verified custody.',
    'source_authority': 'Pinned public source provenance only; no live admission or runtime proof.',
    'source_dependencies': 'F01/F15 engineering accepted exports only. CP090 is not a prerequisite. L01-L08 are runtime interfaces, not build edges.',
}


def positive_integer(value):
    require(type(value) is int and value > 0, 'positive integer required')


def cutoff(value):
    require(type(value) in (int, float) and 0 < value < float('inf'),
            'finite positive window required')


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


NULL = exact(None)
FALSE = exact(False)
UNKNOWN = exact('UNKNOWN')
HOLD = exact('HOLD')
NOT_RUN = exact('NOT_RUN')
OWNER = choice(OWNERS)
FACT = {'value': NULL, 'status': UNKNOWN, 'owner': OWNER, 'source': NULL,
        'version': NULL, 'sha256': NULL, 'evidence': NULL}
ZERO_RESOURCES = {'gpu': exact(0), 'integration': exact(0)}
EFFECT_FLAGS = {name: FALSE for name in EFFECTS}
UNKNOWN_VALUE = {'status': UNKNOWN, 'value': NULL}
REFERENCE = {key: opaque for key in REFERENCE_FIELDS}
REFERENCE.update(version=label, sha256=HEX64)


def validate_reference(value):
    shape(value, REFERENCE)


def validate_synthetic_held(value):
    shape(value, {'synthetic': exact(True), 'task': exact('CP091'),
                  'intent': choice(INTENTS), 'observed_state': UNKNOWN,
                  'controller': opaque, 'generation': positive_integer,
                  'revision': HEX40, 'original_cutoff': cutoff,
                  'pending_receipt': opaque, 'resources': ZERO_RESOURCES,
                  'effects': EFFECT_FLAGS})


def validate_component(value):
    shape(value, {
        'schema_version': exact(1), 'component_id': exact('CP091'),
        'name': exact('OBS Studio; GPU/device passthrough'),
        'source_classification': exact('LEGACY_ISOLATED'),
        'deployment_mode': exact('isolated-preservation-no-activation'),
        'status': HOLD, 'production_authorized': FALSE,
        'native_qualification': NOT_RUN,
        'placement': exact('native-isolated-desktop-proposal'),
        'placement_approved': FALSE,
        'hard_build_prerequisites': exact(['F01', 'F15']),
        'interfaces': exact(['L%02d' % i for i in range(1, 9)]),
        'version': NULL, 'source': NULL, 'digest': NULL, 'edition': NULL,
        'processes': {'persistent': UNKNOWN_VALUE, 'transient': UNKNOWN_VALUE,
                      'new_service': FALSE},
        'runtime_dependencies': NULL,
        'native_db_cache': dict(UNKNOWN_VALUE, note=exact(PUBLIC_TEXT['db_note'])),
        'uid': NULL, 'gid': NULL,
        'ingress': {'allowed': FALSE, 'actual': NULL},
        'egress': {'allowed': FALSE, 'actual': NULL},
        'volumes': NULL, 'secret_references': NULL,
        'health': {'status': UNKNOWN, 'startup_allowed': FALSE, 'readiness': HOLD},
        'migration': {'allowed': FALSE, 'recipe': NULL},
        'backup': {'status': UNKNOWN, 'receipt': NULL},
        'restore': {'status': UNKNOWN, 'autoactivate': FALSE, 'receipt': NULL},
        'rollback': {'status': UNKNOWN, 'recipe': NULL},
        'resources': dict(ZERO_RESOURCES, cpu=exact(1), memory_mib=exact(1536),
                          disk_mib=NULL, pids=NULL, note=exact(PUBLIC_TEXT['resource_note'])),
        'log_redaction': exact(PUBLIC_TEXT['log_redaction']), 'license': NULL, 'sbom': NULL,
        'vulnerability_evidence': NULL, 'unblock_owner': OWNER,
        'acceptance': {'A%d' % i: NOT_RUN for i in range(1, 7)}, 'G02': HOLD,
    })


def validate_compatibility(value):
    shape(value, {'schema_version': exact(1), 'task': exact('CP091'),
                  'status': HOLD, 'facts': {name: FACT for name in FACTS},
                  'qualification': NOT_RUN, 'unblock_owner': OWNER})


def validate_held(value):
    # Actual published UNKNOWN inventory shape is deliberately distinct from
    # the synthetic fixture's fully bound identity. No native identity invented.
    shape(value, {'schema_version': exact(1), 'task': exact('CP091'),
                  'status': HOLD, 'observed_state': UNKNOWN,
                  'intent': choice(INTENTS), 'controller': NULL,
                  'generation': NULL, 'revision': NULL, 'original_cutoff': NULL,
                  'pending_receipt': NULL, 'resources': ZERO_RESOURCES,
                  'effects': EFFECT_FLAGS, 'native_qualification': NOT_RUN,
                  'unblock_owner': OWNER})


def validate_ownership(value):
    shape(value, {'schema_version': exact(1), 'task': exact('CP091'),
                  'status': UNKNOWN, 'verified_custodian': NULL,
                  'unblock_owner': OWNER, 'intent': choice(INTENTS),
                  'intent_evidence': NULL, 'private_inventory': UNKNOWN,
                  'rights': FACT, 'retention': FACT, 'storage': FACT,
                  'restore': FACT, 'controller': UNKNOWN,
                  'pending_receipt': UNKNOWN, 'run_window': UNKNOWN, 'note': exact(PUBLIC_TEXT['ownership_note'])})
    # Non-UNKNOWN intent needs custody/evidence not available in this public
    # preservation packet; do not silently infer stopped/retired from UNKNOWN.
    require(value['intent'] == 'UNKNOWN', 'intent evidence unavailable: HOLD')


def validate_private_contract(value):
    shape(value, {'schema_version': exact(1), 'task': exact('CP091'),
                  'status': HOLD, 'inventory': NULL,
                  'reference_format': exact('opaque:<lowercase-alphanumeric-or-hyphen>'),
                  'required_reference_fields': exact(list(REFERENCE_FIELDS)),
                  'facts_status': UNKNOWN, 'rules': exact([
                      'No private paths, hostnames, account identifiers, scene/config dumps, credentials or assets in public artifacts.',
                      'A sanitized opaque ID is a reference, never authority or proof of custody.',
                      'Actual rights, source version, digest and restore receipt remain null until independently supplied and bound.',
                      'A future reference must bind all required fields; malformed or incomplete claims fail closed.']),
                  'unblock_owner': OWNER})


def public_path(value):
    require(type(value) is str and '\\' not in value and ':' not in value,
            'relative public source path required')
    path = PurePosixPath(value)
    require(not path.is_absolute() and value == path.as_posix() and
            all(part not in ('', '.', '..') for part in value.split('/')),
            'canonical public source path required')


def validate_source_map(value):
    source_row = {
        'group': choice(('control-public', 'accepted-F01', 'accepted-F15', 'legacy-base')),
        'path': public_path, 'revision': HEX40, 'git_blob_oid': HEX40,
        'sha256': HEX64, 'sha256_lf': HEX64, 'pin_match': exact(True),
    }
    ids = array(pattern(r'(?:[A-Z][0-9]{2}-T[0-9]{2}|BASE-[0-9]{3}|B[0-9]{2})'), 576)
    shape(value, {
        'schema_version': exact(1), 'task': exact('CP091'), 'authority': exact(PUBLIC_TEXT['source_authority']),
        'base_revision': exact(BASE_REVISION),
        'public_source_lock_sha256': exact(PUBLIC_LOCK_SHA256),
        'sources': array(lambda row: shape(row, source_row), 503),
        'missing_public_paths': exact([]),
        'source_acceptance': {'count': exact(576),
                              'statuses': {'NOT_RUN': exact(564),
                                           'OPEN_SOURCE_BLOCKER': exact(12)}},
        'traceability': {'count': exact(576), 'statuses': {'NOT_RUN': exact(576)},
                         'ids': ids},
        'native_execution': {'status': NOT_RUN, 'ids': ids},
        'G02': HOLD, 'dependencies': exact(PUBLIC_TEXT['source_dependencies']),
    })
    require(canonical_digest(value['sources']) == SOURCE_ROWS_SHA256,
            'frozen public provenance pins changed')
    require(canonical_digest(value['traceability']['ids']) == SOURCE_IDS_SHA256,
            'frozen source ID identities/order changed')
    require(len(set(value['traceability']['ids'])) == 576 and
            value['native_execution']['ids'] == value['traceability']['ids'],
            'native/source identities differ or duplicate')


VALIDATORS = dict(zip(FILES, (
    validate_component, validate_compatibility, validate_held, validate_ownership,
    validate_private_contract, validate_source_map, validate_synthetic_held,
    validate_reference,
)))


def validate_package(documents):
    """Validate all eight JSON documents with independent explicit schemas."""
    require(type(documents) is dict and set(documents) == set(FILES),
            'all and only published JSON documents required')
    for name, validator in VALIDATORS.items():
        try:
            validator(documents[name])
        except ValueError as exc:
            raise ValueError(name + ': ' + str(exc)) from exc
    held = documents['preservation/held-state.json']
    ownership = documents['preservation/ownership.json']
    component = documents['component.json']
    require(held['intent'] == ownership['intent'], 'cross-file intent mismatch')
    require(held['resources'] == {key: component['resources'][key]
                                for key in ZERO_RESOURCES},
            'cross-file allocation mismatch')
    require(held['native_qualification'] == component['native_qualification'],
            'cross-file qualification mismatch')
    return {'status': 'HOLD', 'documents': len(FILES),
            'native_qualification': 'NOT_RUN', 'G02': 'HOLD'}


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load_package(component_dir):
    root = Path(component_dir).resolve()
    require(root.is_dir() and not Path(component_dir).is_symlink(),
            'regular component directory required')
    documents = {}
    for name in FILES:
        path = root / name
        require(not any(part.is_symlink() for part in
                        (path, *path.parents[:len(Path(name).parts) - 1])),
                'symlinked contract forbidden')
        require(path.is_file() and path.stat().st_size <= 1024 * 1024,
                'bounded regular JSON file required')
        documents[name] = json.loads(
            path.read_text(encoding='utf-8'), object_pairs_hook=no_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError('nonfinite JSON value forbidden')))
    actual = {file.relative_to(root).as_posix() for file in root.rglob('*.json')}
    require(actual == set(FILES), 'unrecognized or missing published JSON')
    return documents


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component-dir', type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        result = validate_package(load_package(args.component_dir))
    except (ValueError, OSError, RecursionError) as exc:
        # Do not emit rejected document content, paths or private values.
        print(json.dumps({'status': 'INVALID', 'error_type': type(exc).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
