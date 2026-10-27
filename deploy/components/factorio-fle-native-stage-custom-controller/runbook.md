# CP090 offline preservation runbook

Status: design only; installation, native recovery/version qualification and original
source acceptance cases NOT_RUN. No service, container, installer, timer, launcher
or always-on controller is supplied. component.json is a non-executable preservation
configuration, not a deployable version pin. Missing pins prevent deployment.

Authority: L01 and the integration contracts require held restoration, original
window checks, one controller owner and external-effect reconciliation. The F01
custody export does not verify the absent raw legacy inventories. F15 site decisions
remain UNSET. Do not execute historical source commands. L01-L08 are related
interfaces, not authorization to activate any legacy workload.

The following procedure is UNEXECUTED and requires a new scoped authorization:
1. The trusted lead assigns the legacy owner and obtains immutable versions,
   edition, architecture, upstream artifact digests, runtime/dependency and native
   DB/cache support evidence, plus original third-party notices.
2. The infrastructure and backup owners privately identify saves, mods, scenarios,
   controller state, pending actions, data ownership, exact backup generation,
   integrity evidence, key custody, retention, RPO/RTO and storage accessibility.
   Missing or inaccessible data is a blocker. Never provision, prune or delete.
3. In a separately approved disposable environment, verify deny networking including
   IPv6 and private disabled RCON; resolve UID/GID and resource ceilings. Preserve
   source media and attribution. This package proves no actual network enforcement.
4. Back up coherently under the owner-approved native procedure; verify integrity
   without exposing private payloads. Restore a copy in isolation with controller
   and autostart disabled. Verify save/mod/scenario compatibility and inventory.
5. Restart, restore and rollback retain held/stopped/retired intent. Reconcile
   uncertain external receipts and pending actions against authoritative state.
   UNKNOWN remains HOLD and is never permission to replay. Rollback preserves
   newer receipts and cannot undo external effects.
6. A future resume requires a separate human gate bound to exact revision, current
   owner, original unextended run window and one controller ownership receipt.
   Ended windows cannot be revived here. This package always returns HOLD.

Synthetic validation: run Python 3.14 unittest discovery in tests with -B.
preservation.py is an offline decision model, not a native runtime or durable
idempotency ledger. Its prerequisite inputs are synthetic, not verified approvals.
No positive activation path exists.

Independent verifier, exact candidate CI, disclosure/history checks and required
Copilot clearance are owned by the trusted lead and remain pending. No acceptance
or merge receipt is supplied.
