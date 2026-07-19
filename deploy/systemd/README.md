# Add systemd + tmpfs enforcement

Files
- `add-bootstrap.service` — bootstrap DHT daemon
- `add-relay.service` — relay / mailbox daemon
- `add-tmpfs.conf` — tmpfiles.d rule mounting `/root/.add` on tmpfs at boot
- install via `scripts/install-systemd.sh <host>`

Threat model
A cloud hypervisor can snapshot the VM's RAM and disk at any instant, or clone the
block device offline. If daemon state (DHT DB, key material) lives on a persistent
filesystem, an attacker with disk/backup access recovers it at rest. Mounting the
state dir on **tmpfs** keeps it in RAM and wipes it on reboot.

How the two layers reinforce each other
1. `add-tmpfs.conf` mounts `/root/.add` as tmpfs (RAM-only) at boot.
2. The service units set `ADD_REQUIRE_TMPFS=1`, so the daemon panics at boot
   unless that dir is genuinely tmpfs — guaranteeing the layer-1 mount actually took.

Hardening applied in the units
- `CapabilityBoundingSet=CAP_IPC_LOCK` + `AmbientCapabilities=CAP_IPC_LOCK` — the only
  capability granted, so the daemon's `mlock`/`mlockall` (used to pin key pages) succeeds.
- `ProtectHome=tmpfs`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`,
  `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `RestrictNamespaces`/`SUID`/`SUIDGID`,
  `SystemCallFilter=@system-service` — standard systemd attack-surface reduction.

Rollback / non-enforcement
To run on a persistent filesystem (dev/test), drop `ADD_REQUIRE_TMPFS=1` from the
unit (or leave the env unset — the daemon then only warns). The tmpfs mount is optional;
without it the daemon still runs (warn-only) as before.

Snapshot-Resistant Key Custody (SSS)
At boot each daemon builds a `SecKit` (`crypto::snapshot_defense`): it generates a volatile
AES-256 key, splits it 2-of-3 via Shamir over GF(2^8), and writes one shard to each of three
local "OHT" provider dirs (`oht-0/1/2/shard.bin`) under the state dir. The key is proven via
a seal/open round-trip and then dropped — it lives in RAM only for that boot window
(mlock-pinned, excluded from core dumps, zeroized on drop). Shards persist so the next restart
recovers the SAME key from any two of three. Losing one shard (provider down) is tolerated;
losing two mints a fresh kit (disaster recovery). With `ADD_REQUIRE_TMPFS=1`, the daemon
panics before persisting shards if the state dir is not genuine tmpfs — so the cleartext
shards never land on a persistent disk. (The three local dirs stand in for real OHT endpoints;
the SSS math, persistence, and recovery are fully implemented and tested.)

Caveats
- CAP_IPC_LOCK lets the daemon lock an unbounded amount of RAM; the crypto module only
  locks small key/shard buffers, so this is bounded in practice.
- tmpfs state is volatile: a reboot loses DHT/relay state until re-registration. The
  bootstrap DHT is replicated across the 3 regions, so a single node's loss is tolerable.
