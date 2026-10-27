#!/usr/bin/env bash
# Offline public contracts only. Structural checks never qualify native recovery.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

for mode in normal optimized; do
  optimization=()
  if [[ "$mode" == optimized ]]; then
    optimization=(-O)
  fi
  python3 -B "${optimization[@]}" - "$mode" <<'PY'
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

PACKAGE = Path("deploy/components/herdr-coven-custom-agent-harness-processes")
EXPECTED_TESTS = 11
MODE = sys.argv[1]


def check(condition, reason):
    # Explicit checks survive -O; no assert or text/grep success inference.
    if not condition:
        raise SystemExit("CP092_CI_REJECTED: " + reason)


check(MODE in ("normal", "optimized"), "unknown interpreter mode")
check(sys.flags.optimize == (1 if MODE == "optimized" else 0),
      "interpreter optimization mismatch")
loader = unittest.TestLoader()
suite = loader.discover(str(PACKAGE / "tests"), pattern="test_preservation_contract.py")
check(not loader.errors, "test discovery errors")
check(suite.countTestCases() == EXPECTED_TESTS, "discovered test count differs from 11")
transcript = io.StringIO()
result = unittest.TextTestRunner(stream=transcript, verbosity=2).run(suite)
counts = {
    "discovered": EXPECTED_TESTS,
    "executed": result.testsRun,
    "skipped": len(result.skipped),
    "failures": len(result.failures),
    "errors": len(result.errors),
    "expected_failures": len(result.expectedFailures),
    "unexpected_successes": len(result.unexpectedSuccesses),
}
print(json.dumps({"mode": MODE, "unittest": counts}, sort_keys=True), flush=True)
complete = (result.testsRun == EXPECTED_TESTS and not result.skipped
            and not result.failures and not result.errors
            and not result.expectedFailures and not result.unexpectedSuccesses
            and result.wasSuccessful())
if not complete:
    print(transcript.getvalue(), end="", flush=True)
check(complete, "11 executed tests with zero skips/failures/errors required")

# Run actual CLI separately under each interpreter mode: optimization of this
# runner alone does not propagate to child Python processes.
python_flags = ["-B"] + (["-O"] if MODE == "optimized" else [])
validator = PACKAGE / "preservation" / "validate_contracts.py"
valid_output = b"CP092_VALID: structural HOLD only; no native qualification or activation\n"
blocked_output = b"CP092_BLOCKED: native evidence UNKNOWN; G02 HOLD; all native AC NOT_RUN\n"
cli_checks = []
for fixtures in (False, True):
    for readiness in (False, True):
        arguments = [sys.executable] + python_flags + [str(validator), str(PACKAGE)]
        if fixtures:
            arguments.append("--include-fixtures")
        if readiness:
            arguments.append("--require-native-ready")
        expected_code = 2 if readiness else 0
        expected_output = blocked_output if readiness else valid_output
        try:
            completed = subprocess.run(arguments, capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise SystemExit("CP092_CI_REJECTED: CLI unavailable or timed out") from None
        check(completed.returncode == expected_code, "CLI exit code mismatch")
        check(completed.stderr == b"", "CLI stderr must be empty")
        check(completed.stdout == expected_output, "CLI exact structural/HOLD output mismatch")
        cli_checks.append({"fixtures": fixtures, "require_native_ready": readiness,
                           "exit_code": completed.returncode})
print(json.dumps({"mode": MODE, "cli": cli_checks,
                  "evidence_level": "OFFLINE_PUBLIC_CONTRACT_ONLY",
                  "native_qualification": "NOT_RUN", "production_gate": "G02_HOLD"},
                 sort_keys=True), flush=True)
PY
done
