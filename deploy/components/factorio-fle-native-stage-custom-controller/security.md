# Security boundary and evidence

LEGACY_ISOLATED / isolated-preservation-no-activation is justified by L01's existing
native runtime and preserve-intent failure contract. No upstream artifact has been
selected, so no fabricated Containerfile, Quadlet, digest or runtime license is
provided. The container/host baseline remains applicable to a future scoped runtime.

All entry points here are pure functions. There are no subprocesses, sockets,
runtime starts, native probes, secret reads, installs or provider operations.
Manifest deny settings express intent; actual host/network enforcement is NOT_RUN.
RCON must remain private and disabled. No marketing credential may be attached.

Evidence uses fixed allowlisted enum values and discards every untrusted input;
do not add raw exceptions, requests or arbitrary strings to logs. Secret references
are unknown, never sample secret values. The repository MIT decision does not
relicense Factorio, FLE, mods or other third-party artifacts; preserve original
notices and obtain exact license evidence before copying any runtime artifacts.

SBOM, vulnerability scanning, actual resource enforcement, storage integrity,
backup usability, native health and restore compatibility remain unknown/NOT_RUN.
Requested unblock roles: Platform owner (versions, dependencies, notices, SBOM),
Security owner (secret references and vulnerability evidence), Service owner
(runtime identity and current ownership), Infrastructure owner (storage, networking
and limits), Backup owner (backup identity and tested held recovery), and trusted
lead (lease/fence, original window, independent verification and integration).

Synthetic negative tests establish local decision behavior only. They cannot
establish authentication, authorization, firewall effectiveness or durable dedupe
for an actual Factorio/FLE controller. No original source acceptance is promoted.
