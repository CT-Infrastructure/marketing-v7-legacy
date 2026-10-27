# Offline synthetic contract tests

The standard-library module is a local contract reference and tests only synthetic data. It provides no deployment/runtime controller. Run from this component directory, only under a separately authorized scoped test job:

```text
python -B -m unittest discover -s tests -p test_preservation_contract.py -v
python -B -O -m unittest discover -s tests -p test_preservation_contract.py -v
```

Authoring admission permits AST parsing only; execution receipts must be supplied by the authorized test executor. Tests use no network, host/device inspection, real assets or private inventory. The synthetic raw-JSON regression launches a fixed local validator subprocess using the current Python interpreter (`sys.executable -B`, with `-O` in optimized mode), the public `preservation/validate_contracts.py` script and `--component-dir` pointing to a synthetic temporary package. It captures stdout/stderr and applies a 15-second timeout. Execution requires root admission; the child inherits the authorized executor sandbox and isolation controls. This local CLI check provides no OBS, vendor, device or native-runtime qualification. Validators use explicit exceptions, not assert, so optimized-mode checks retain protection. Native tests, all 576 original acceptance IDs, production G02, real restore/power loss, sandbox/egress enforcement, independent reviewer and exact-head CI/Codex remain unqualified. These tests cannot accept CP091.


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
