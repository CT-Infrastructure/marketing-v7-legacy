"""Offline CP091 contract model; no native actions or acceptance authority."""
import copy
import json
from pathlib import Path
import re
import unittest

BASE = Path(__file__).resolve().parents[1]
OPAQUE = re.compile(r"opaque:[a-z0-9]+(?:-[a-z0-9]+)*\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")
EFFECTS = {'autostart', 'capture', 'broadcast', 'recording', 'device_attach',
           'network', 'restore_activation', 'migration', 'delete'}
HELD_KEYS = {'synthetic', 'task', 'intent', 'observed_state', 'controller',
             'generation', 'revision', 'original_cutoff', 'pending_receipt',
             'resources', 'effects'}
REFERENCE_KEYS = {'id', 'custodian', 'source', 'version', 'sha256', 'evidence',
                  'rights', 'retention', 'restore'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def opaque(value):
    require(type(value) is str and OPAQUE.fullmatch(value) is not None,
            'sanitized opaque reference required')
    require(not any(x in value.lower() for x in
                    ('secret', 'token', 'password', 'credential', 'private-key')),
            'secret-like reference forbidden')


def public_label(value):
    require(type(value) is str and
            re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}', value) is not None,
            'bounded public label required')
    require(not any(x in value.lower() for x in
                    ('secret', 'token', 'password', 'credential', 'private-key')),
            'secret-like label forbidden')


def validate_reference(value):
    require(type(value) is dict and set(value) == REFERENCE_KEYS,
            'exact private reference fields required')
    for key in REFERENCE_KEYS - {'version', 'sha256'}:
        opaque(value[key])
    public_label(value['version'])
    require(type(value['sha256']) is str and DIGEST.fullmatch(value['sha256'])
            is not None, 'exact digest required')
    return 'REFERENCE_ONLY'


def validate_held(value):
    require(type(value) is dict and set(value) == HELD_KEYS,
            'exact synthetic held fields required')
    require(value['synthetic'] is True and value['task'] == 'CP091',
            'synthetic CP091 only')
    require(value['intent'] in ('UNKNOWN', 'HELD', 'STOPPED', 'RETIRED'),
            'unknown/held/stopped/retired intent required')
    require(value['observed_state'] == 'UNKNOWN', 'no native observation')
    opaque(value['controller'])
    opaque(value['pending_receipt'])
    require(type(value['generation']) is int and value['generation'] > 0,
            'positive integer generation required')
    require(type(value['revision']) is str and REVISION.fullmatch(value['revision'])
            is not None, 'exact revision required')
    require(type(value['original_cutoff']) in (int, float) and
            0 < value['original_cutoff'] < float('inf'), 'finite cutoff required')
    require(type(value['resources']) is dict and
            set(value['resources']) == {'gpu', 'integration'}, 'resource fields')
    for resource in ('gpu', 'integration'):
        require(type(value['resources'][resource]) is int and
                value['resources'][resource] == 0, 'zero allocation required')
    require(type(value['effects']) is dict and set(value['effects']) == EFFECTS,
            'exact effect flags required')
    require(all(type(flag) is bool and flag is False
                for flag in value['effects'].values()), 'effects must be false')
    return 'HOLD'


def restore_synthetic(saved, current, controllers):
    """JSON roundtrip model only. Never restores native data or effects."""
    validate_held(saved)
    validate_held(current)
    require(type(controllers) is list and controllers == [current['controller']],
            'single current controller required')
    for key in ('task', 'controller', 'generation', 'revision', 'original_cutoff',
                'pending_receipt', 'resources', 'intent'):
        require(saved[key] == current[key], 'stale or mismatched ' + key)
    result = json.loads(json.dumps(saved, allow_nan=False))
    result['effects'] = dict.fromkeys(EFFECTS, False)
    validate_held(result)
    return result


def fact_status(fact):
    keys = {'value', 'status', 'owner', 'source', 'version', 'sha256', 'evidence'}
    require(type(fact) is dict and set(fact) == keys, 'exact fact fields')
    require(type(fact['owner']) is str and bool(fact['owner'].strip()), 'owner required')
    if fact['status'] == 'UNKNOWN':
        require(all(fact[k] is None for k in
                    ('value', 'source', 'version', 'sha256', 'evidence')),
                'UNKNOWN cannot contain claims')
        return 'HOLD'
    require(fact['status'] == 'EVIDENCE_SUPPLIED', 'no asserted qualification')
    public_label(fact['value'])
    opaque(fact['owner'])
    opaque(fact['source'])
    opaque(fact['evidence'])
    public_label(fact['version'])
    require(type(fact['sha256']) is str and DIGEST.fullmatch(fact['sha256'])
            is not None, 'exact digest required')
    # Supplied references never establish native approval.
    return 'HOLD'


class PreservationContractTests(unittest.TestCase):
    def setUp(self):
        self.held = json.loads((BASE / 'tests/fixtures/synthetic-held.json').read_text())
        self.ref = json.loads((BASE / 'tests/fixtures/synthetic-private-reference.json').read_text())

    def test_fixture_roundtrip_preserves_identity_and_hold(self):
        before = copy.deepcopy(self.held)
        restored = restore_synthetic(self.held, before, [before['controller']])
        self.assertEqual(restored, before)
        self.assertEqual(self.held, before)
        self.assertIsNot(restored, self.held)
        self.assertEqual(validate_held(restored), 'HOLD')

    def test_intents_remain_distinct_and_never_qualify(self):
        results = []
        for intent in ('UNKNOWN', 'HELD', 'STOPPED', 'RETIRED'):
            self.held['intent'] = intent
            restored = restore_synthetic(self.held, self.held, [self.held['controller']])
            results.append(restored['intent'])
            self.assertEqual(validate_held(restored), 'HOLD')
        self.assertEqual(len(set(results)), 4)
        self.held['intent'] = 'ABSENT'
        with self.assertRaises(ValueError):
            validate_held(self.held)

    def test_every_effect_rejects_activation_and_malformed_boolean(self):
        for key in EFFECTS:
            for bad in (True, 0, 1, None, '', 'false', [], {}):
                candidate = copy.deepcopy(self.held)
                candidate['effects'][key] = bad
                with self.subTest(key=key, bad=repr(bad)), self.assertRaises(ValueError):
                    restore_synthetic(candidate, self.held, [self.held['controller']])

    def test_stale_or_wrong_identity_is_rejected(self):
        changes = {'controller': 'opaque:other-controller', 'generation': 2,
                   'revision': 'c' * 40, 'original_cutoff': 999,
                   'pending_receipt': 'opaque:other-pending', 'intent': 'STOPPED'}
        for key, replacement in changes.items():
            saved = copy.deepcopy(self.held)
            saved[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                restore_synthetic(saved, self.held, [self.held['controller']])

    def test_duplicate_missing_or_wrong_controller_rejected(self):
        controller = self.held['controller']
        for controllers in ([], [controller, controller], ['opaque:other'], None, controller):
            with self.subTest(controllers=controllers), self.assertRaises(ValueError):
                restore_synthetic(self.held, self.held, controllers)

    def test_zero_allocations_are_typed_and_enforced(self):
        for resource in ('gpu', 'integration'):
            for value in (1, -1, False, '0', None):
                bad = copy.deepcopy(self.held)
                bad['resources'][resource] = value
                with self.subTest(resource=resource, value=value), self.assertRaises(ValueError):
                    validate_held(bad)

    def test_generation_revision_and_window_types(self):
        for key, values in {'generation': (True, 0, '1'),
                            'revision': ('latest', 'A'*40, None),
                            'original_cutoff': (True, 0, float('nan'), float('inf'))}.items():
            for value in values:
                bad = copy.deepcopy(self.held)
                bad[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    validate_held(bad)

    def test_missing_and_extra_fields_rejected(self):
        for key in HELD_KEYS:
            bad = copy.deepcopy(self.held)
            del bad[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_held(bad)
        self.held['commands'] = []
        with self.assertRaises(ValueError):
            validate_held(self.held)

    def test_private_reference_is_only_reference(self):
        self.assertEqual(validate_reference(self.ref), 'REFERENCE_ONLY')

    def test_private_paths_secrets_and_uris_rejected(self):
        for key in REFERENCE_KEYS - {'sha256'}:
            for value in ('/home/private/scene', 'C:\\private\\scene', '../secret',
                          'https://private.example', 'opaque:password-value',
                          'token=abc', 'password', 'opaque:synthetic\nvalue'):
                bad = dict(self.ref, **{key: value})
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    validate_reference(bad)

    def test_missing_custody_source_version_and_evidence_rejected(self):
        for key in REFERENCE_KEYS:
            for value in (None, '', False):
                bad = dict(self.ref, **{key: value})
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    validate_reference(bad)
        self.ref['private_path'] = 'not-allowed'
        with self.assertRaises(ValueError):
            validate_reference(self.ref)

    def test_digest_malformed_and_evidence_claims_rejected(self):
        for digest in ('a'*63, 'a'*65, 'A'*64, 'sha256:'+'a'*64, True):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                validate_reference(dict(self.ref, sha256=digest))
        for claim in (True, 1, 'PASS', {'approved': True}):
            with self.subTest(claim=claim), self.assertRaises(ValueError):
                validate_reference(dict(self.ref, evidence=claim))

    def test_unknown_facts_hold_and_cannot_hide_claims(self):
        facts = json.loads((BASE/'preservation/compatibility.json').read_text())['facts']
        for key, fact in facts.items():
            self.assertEqual(fact_status(fact), 'HOLD', key)
            for field in ('value', 'source', 'version', 'sha256', 'evidence'):
                bad = dict(fact, **{field: 'invented'})
                with self.subTest(key=key, field=field), self.assertRaises(ValueError):
                    fact_status(bad)
            with self.assertRaises(ValueError):
                fact_status(dict(fact, owner=None))

    def test_supplied_evidence_never_promotes_native_acceptance(self):
        fact = {'value': 'synthetic-v1', 'status': 'EVIDENCE_SUPPLIED',
                'owner': self.ref['custodian'], 'source': self.ref['source'],
                'version': self.ref['version'], 'sha256': self.ref['sha256'],
                'evidence': self.ref['evidence']}
        self.assertEqual(fact_status(fact), 'HOLD')
        for field in ('owner', 'source', 'version', 'sha256', 'evidence'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                fact_status(dict(fact, **{field: None}))
        with self.assertRaises(ValueError):
            fact_status(dict(fact, status='APPROVED'))

    def test_package_keeps_all_native_ids_not_run(self):
        source = json.loads((BASE/'preservation/source-map.json').read_text())
        ids = source['native_execution']['ids']
        self.assertEqual(len(ids), 576)
        self.assertEqual(len(set(ids)), 576)
        self.assertEqual(source['native_execution']['status'], 'NOT_RUN')
        self.assertEqual(source['traceability']['statuses'], {'NOT_RUN': 576})
        self.assertEqual(source['source_acceptance']['statuses'],
                         {'NOT_RUN': 564, 'OPEN_SOURCE_BLOCKER': 12})
        self.assertEqual(source['G02'], 'HOLD')
        component = json.loads((BASE/'component.json').read_text())
        self.assertIs(component['production_authorized'], False)
        self.assertEqual(set(component['acceptance'].values()), {'NOT_RUN'})
        self.assertEqual(component['resources']['gpu'], 0)
        self.assertEqual(component['resources']['integration'], 0)


if __name__ == '__main__':
    unittest.main()
