# CP092 offline regression evidence

Author status: NOT_RUN. This folder contains stdlib regression source and two
synthetic fixtures with schemas distinct from actual native contracts. Tests
load the actual published component and preservation JSON and mutate those
shapes. Native Herdr/Coven sessions, logs, databases, processes, APIs, credentials
and host state must never be test inputs.

Use the normal and optimized unittest commands in ../runbook.md in an authorized
isolated Linux Python 3.10+ executor. They include real validator CLI checks for
success 0, readiness blocked 2 and malformed input 1; fixed redacted error output;
deep JSON ValueError/RecursionError portability; duplicate/nonfinite/encoding/
size/node limits; source and acceptance closure; ownership/cutoff/generation/
revision continuity; native facts; safety/resource flags; opaque private IDs;
locator forms; restore HOLD; and symlink/traversal rejection. A Windows symlink
privilege skip is a limitation requiring Linux execution before acceptance.

The actual-leaf mutation regression checks all published leaves; it can take
longer than focused tests. It is finite and operates on bounded source data.
Record command codes, candidate revision, executor identity and artifact hashes
outside this author record. Root must also perform a broken-checker/old-new
regression demonstration and fresh independent review/CI at the exact candidate.
Do not mark the 576 source acceptance cases or six native acceptance conditions
PASS from these tests. Offline contract validation, source custody, independent
review, native recovery qualification and production approval are separate.
