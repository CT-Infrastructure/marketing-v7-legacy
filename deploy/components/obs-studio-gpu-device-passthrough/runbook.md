# CP091 preservation runbook

Current outcome: UNKNOWN inventory, HOLD execution, G02 HOLD. All 576 original native acceptance IDs remain NOT_RUN. Source acceptance contains 564 NOT_RUN and 12 OPEN_SOURCE_BLOCKER; the source-map retains this distinction. No installation, device activation, stream, recording, restore or network operation is authorized.

1. Legacy custodian supplies sanitized custody and intent evidence through an approved private channel. Preserve held, stopped and retired as distinct intents; UNKNOWN never means absent, stopped, retired or approved. Keep private evidence outside this repository, referenced only by opaque identifiers. Do not discover private inventory from this package.
2. Platform owner supplies exact versions/source/digests and compatibility evidence in compatibility.json. Rights/privacy and backup owners supply asset rights, retention, storage and restore receipts. Missing fields remain null/UNKNOWN; never substitute a current/latest release or a guessed hash.
3. Trusted controller independently reconciles the same run identity, owner, generation, revision, original cutoff, GPU/integration reservations and pending receipts before any future action. A stale receipt, uncertain external operation or duplicate controller requires HOLD and reconciliation. Do not retry an uncertain external effect.
4. Backup/restore procedure is blocked pending an approved private artifact locator, custody/retention policy, exact artifact hashes and a separately allocated disposable scope. A future owner copies only authorized data into that scope, verifies hashes and restores with all startup/output/device/network switches disabled. Compare identity, generation, revision, original cutoff and pending receipts against the trusted current record. Native power-loss/restart/rollback and usable-backup acceptance require independent receipts; synthetic serialization is not that proof.
5. Rollback must preserve original evidence and pending receipts, return to held execution and reconcile any uncertain side effect before future activation. No deletion, migration, retirement or restore automatically follows from HOLD. Never restore autostart, credentials, device attachment, broadcast, capture or recording.
6. Stop on expired/revoked lease, scope change, secret exposure or uncertain effects. Notify the retained owner/trusted controller; do not create another controller or extend a cutoff. Never shut down or terminate WSL.

A1 native compatibility, A2 disposable installation, A3 real sandbox/egress enforcement, A4 native backup/restore, A5 placement approval and A6 independent exact-candidate verification remain NOT_RUN. Offline tests cover contract rejection and held serialization only. Root owns independent review, exact-head CI/Codex, import and acceptance. Engineering review readiness never grants production authority.


The offline public-package validator now checks all eight actual JSON documents,
including ownership, held-state and private-artifact wrappers. It uses distinct
schemas for nullable UNKNOWN public identities and synthetic bound fixtures;
exact keys/types/fact names/A1-A6, false safety flags, cross-file consistency,
frozen provenance rows and all 576 source IDs fail closed. Frozen hashes bind
public provenance/ID identity only, not a blanket expected-package pass fixture.
No native facts are filled by validation, and a successful result remains HOLD.
A future supplied native inventory requires separately reviewed schema changes.

Under an authorized scoped executor, from the component directory:

```text
python -B preservation/validate_contracts.py
python -B -O preservation/validate_contracts.py
python -B -m unittest discover -s tests -p test_preservation_contract.py -v
python -B -O -m unittest discover -s tests -p test_preservation_contract.py -v
```

The CLI returns 1 for invalid/missing/duplicate-key or unrecognized JSON and
prints a bounded generic error without rejected values. New regression tests
mutate copies of the actual published shapes for R1's old-unchecked fields;
no on-disk native/configuration data is modified. The original 15 test methods
and assertions remain. Source-author AST/JSON parsing is not execution evidence;
authorized exact-source normal/optimized runs and independent review remain due.
R2's old optimized seven-check receipt remains historical and is superseded only
by separately sealed controller-owned corrected operational evidence.
