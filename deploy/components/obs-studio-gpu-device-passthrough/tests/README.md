# Offline synthetic contract tests

The standard-library module is a local contract reference and tests only synthetic data. It provides no deployment/runtime controller. Run from this component directory, only under a separately authorized scoped test job:

```text
python -B -m unittest discover -s tests -p test_preservation_contract.py -v
python -B -O -m unittest discover -s tests -p test_preservation_contract.py -v
```

Authoring admission permits AST parsing only; execution receipts must be supplied by the authorized test executor. Tests use no network, host/device inspection, subprocesses, real assets or private inventory. Validators use explicit exceptions, not assert, so optimized-mode checks retain protection. Native tests, all 576 original acceptance IDs, production G02, real restore/power loss, sandbox/egress enforcement, independent reviewer and exact-head CI/Codex remain unqualified. These tests cannot accept CP091.
