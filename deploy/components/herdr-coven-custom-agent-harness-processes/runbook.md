# CP092 historical coding-session preservation

This package is a bounded offline contract, not an installer, session inventory,
backup, process controller or activation tool. Its role is historical coding
sessions under LEGACY_ISOLATED / isolated-preservation-no-activation. Source
registry enabled_by_default describes task eligibility, not native activation.
Only accepted F01 and F15 are hard prerequisites; CP090 and CP091 are not.
L03 is the direct coding-session design. L01–L08 are related interfaces, not
proof those workloads exist or are qualified. No OBS-specific facts are reused.

`component.json` records all required native inventory fields as null UNKNOWN
with an unblock role, public source ID and null evidence. Exact Herdr/Coven/
harness versions, editions, runtime dependencies, databases/caches, processes,
UID/GID, state roots, ownership, health, limits, licenses, SBOM, vulnerability,
backup/restore and rollback facts are unavailable. Persistent and transient
process fields are separate UNKNOWN facts. Zero package resources mean no
deployed workload reservation; native resource limits remain UNKNOWN, never zero
as a guessed native limit. No container or Quadlet is appropriate for a contract
that does not launch anything. Compatibility and installation remain blocked.

## Public evidence and limits

`preservation/source-map.json` closes over all 503 provided public source-lock
rows, retaining source identity, group, exact revision, blob and byte/LF hashes.
The first 413 are control-public, then 6 accepted F01 and 9 accepted F15, then
75 legacy-base rows. These pins are custody references, not live ancestry or
admission proof. F01 retains 156 disposition, 104 recovery and 69 route opaque
references; raw evidence is absent and unverified. Never label inaccessible
native state absent. All 576 original acceptance cases remain NOT_RUN with no
evidence; all six CP092 native acceptance cases remain NOT_RUN. Offline source
checks do not promote either evidence level.

Author byte inspection matched 502 original materialized lock rows. For SRC-503,
root supplied a separately hashed read-only context appendix and both raw CI
blobs: locked d058 (559 bytes, 28d08...) and current base 8a765 (1130 bytes,
52d4...). Both raw hashes were independently checked by the author; root reports
ancestry and the legitimate CP091 CI overlay. The source map binds the locked
source to its old revision and records current base separately, with no pin
waiver. No CI file or original source lock was changed. The appendix hash is
recorded. Author byte checks do not independently prove Git ancestry or admission.

## Offline executor handoff

The author performed static authoring only. In a separately authorized stable
isolated Python 3.10+ standard-library environment, from repository root:

```text
python -B deploy/components/herdr-coven-custom-agent-harness-processes/preservation/validate_contracts.py deploy/components/herdr-coven-custom-agent-harness-processes --include-fixtures
python -B deploy/components/herdr-coven-custom-agent-harness-processes/preservation/validate_contracts.py deploy/components/herdr-coven-custom-agent-harness-processes --require-native-ready
python -B -m unittest discover -s deploy/components/herdr-coven-custom-agent-harness-processes/tests -p test_preservation_contract.py -v
python -B -O -m unittest discover -s deploy/components/herdr-coven-custom-agent-harness-processes/tests -p test_preservation_contract.py -v
```

Validator exit 0 means only a structurally valid immutable UNKNOWN/HOLD package;
exit 1 means malformed/changed/unsafe contract; exit 2 means native readiness is
blocked. The readiness command must return 2. It has no activation mode. Capture
actual codes, exact candidate revision, independent executor/reviewer identities,
command output and artifact hashes. Root must run fresh review and required CI;
author tests are NOT_RUN. Rebase or edits require exact-candidate revalidation.

The validator compares closed, typed baselines for the actual published JSON.
The 503 ordered source identities and pins have a fixed aggregate fingerprint;
576 ordered acceptance IDs have a separate fingerprint. Changing a baseline or
fingerprint is a separately reviewed code change, never approval of native facts.
Synthetic fixture schemas are intentionally distinct and cannot stand in for
native ownership, session continuity, private custody or actual restore evidence.
The tool reads only fixed contract filenames beneath the explicit package root;
no private references are resolved. It rejects duplicate keys, nonfinite values,
UTF-8 BOM/invalid encoding, extra fields, changed safety facts, oversized/deep
inputs, symlink/junction ancestors and path traversal. Errors are fixed, redacted
and bounded. Run on a stable snapshot; concurrent hostile filesystem races are
outside this offline design.

## Future private preservation work: blocked, separate authority required

The accountable legacy owner and private custodian must provide minimally
necessary authenticated evidence in their authorized private system. Do not
infer ownership from a process name, model name, host or VM name. Distinguish
host Coven and Herdr VM state roots without publishing either locator. Inventory
worktrees including uncommitted work, session databases and sidecars, lock files,
pending actions, durable receipts and failure history. Keep credentials protected
under existing custody; do not copy values into this package or add marketing
credentials. Public output uses only opaque references, never locations.

Preserve the exact current owner/controller/session, generation, revision and
original cutoff. UNKNOWN values here are not permission to choose replacements.
Keep HELD, STOPPED and RETIRED intent distinct. Lease expiry does not prove the
old controller dead; one reconciled current controller is required. Preserve
pending receipts and uncertain outcomes, never reset or automatically retry.
An expired original window or intentional stop cannot be extended by restore.

After separately authorized coherent backup and isolated restore, restoration
must return to HOLD with autonomous actions disabled. Reconcile originals,
locks, pending effects/receipts and ownership before any separately approved
one-owner decision. Uncertain effects remain HOLD_NO_RETRY. No script here
performs copying, restarting, migration, pruning, deletion or replay. Native
backup usability and rollback remain NOT_RUN pending that separate exercise.
Rolling back this package means a trusted integrator reverts only these public
contract files while retaining review/receipt history; no deployed state changes.
G02 and all production effects remain HOLD. GitHub engineering acceptance does
not replace OpenProject business/publication decisions or native authorities.
