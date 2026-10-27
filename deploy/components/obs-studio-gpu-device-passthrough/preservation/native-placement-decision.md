# Native placement proposal — HOLD

CP091 preserves historical capture/broadcast evidence under LEGACY_ISOLATED. OBS is a native desktop application with OS, graphics, capture, plugin and encoder dependencies whose exact versions and compatibility are UNKNOWN. An isolated desktop guest is a proposal requiring platform and infrastructure owner approval, not an installed target. No empty Containerfile, Quadlet, service or device-mount recipe is provided.

A1: OBS/OS/architecture, Qt/FFmpeg/plugin ABI, GPU/driver/encoder/SRT, upstream artifact digest, license and SBOM require exact independently sourced evidence. A2: installation is blocked on those pins and an approved disposable environment; no installer/latest version is selected. A5: actual placement and native security controls remain NOT_RUN. UID/GID, DB/cache, process inventory and storage are UNKNOWN, not absent.

GPU=0 and integration=0 prohibit native attachment/validation in this contribution. Future owners must reserve a disposable integration environment, approve a scoped native installation/rollback recipe and prove resource/egress/device isolation without affecting shared workloads. F01/F15 engineering acceptance does not prove any native control or G02 approval.
