# PkgSentinel — Sandbox Controller

Dedicated, isolated micro-service that manages the lifecycle of ephemeral, unprivileged Docker canary containers.

In accordance with Architecture v2.1:
- The general-purpose Python Security Worker **never** mounts `/var/run/docker.sock`.
- Only this dedicated controller interacts with the container runtime.
- In production, canaries run with `--security-opt=no-new-privileges:true`, `CAP_DROP ALL`, and `gVisor (runsc)`.
- Egress is strictly routed to the Sinkhole Gateway with no external WAN routing.

*Scheduled for full implementation in Phase 2.*

