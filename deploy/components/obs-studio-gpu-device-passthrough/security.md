# Security boundary

This package contains inert public contracts and synthetic fixtures. It has no installer, command runner, network client, OBS API, device interface, service, credential loader or production activation path. Contract rejection tests are application-level offline checks, not proof of OS permissions, sandboxing, egress enforcement or native isolation.

Only sanitized opaque artifact references are allowed. Reject local/private paths, URIs, credentials, scene/profile dumps, secret-like strings and extra unreviewed fields. Referenced evidence must have a custodian, source, version, digest, rights, retention and restore binding; references alone prove none of these. Actual artifacts stay with their private custodian. Null/UNKNOWN is valid preservation data but cannot qualify a native gate.

Future separately authorized native work must apply the container/native baseline: least privilege, reviewed device scope, no arbitrary mounts or host sockets, bounded CPU/RAM/PIDs/disk/GPU/VRAM, explicit IPv4/IPv6/DNS/proxy/metadata denies, redacted logs, source integrity, license/SBOM/vulnerability review and an isolated rollback plan. Current GPU/integration reservations are zero. This package neither enforces nor claims these host controls.

Held restore requires exact trusted owner/revision/generation/window/pending-receipt reconciliation and a single controller. Every external-effect flag must be the boolean false; strings and numeric substitutes are rejected. Unknown, held, stopped and retired remain distinct. Restore cannot activate outputs, restart services, migrate or delete assets. Production G02 remains HOLD and all original native IDs remain NOT_RUN.
