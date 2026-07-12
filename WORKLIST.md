# ACS2.6 Implementation Worklist — First App Audit

**Date:** 2026-07-06 (updated 2026-07-09)
**Spec:** ACS2.6.md (Architectural & Cryptographic Specification v2.6)
**Current state:** **11/11 Core Requirements Implemented** — 33 ACS2.6 specification items tracked across 6 parts. Core messaging + metadata protection + local storage hardening complete. Remaining items are mobile/push, group messaging, OHT, attestation, and jurisdictional features. **SPQR Braid is now fully wired into the live P2P handshake + ratchet (v0.3.16); the old `crypto::BraidState` ct1/ct2 design was removed as broken dead code.**

> **Documentation:** [README.md](README.md) · [DEVELOPER.md](DEVELOPER.md) · [FAQ.md](FAQ.md) · [CHANGELOG.md](CHANGELOG.md) · [ACS2.6.md](ACS2.6.md)

---

## Legend

- ✅ = Implemented and wired end-to-end
- 📦 = Library exists but not integrated end-to-end
- ⚠️ = Partially implemented (library + partial wiring)
- ❌ = Not implemented
- 🔴 = Priority blocker for "first app"
- 🟡 = Important for first app but not blocking
- 🟢 = Can defer to v2.6 follow-up

---

## PART I: Core P2P Messaging & Metadata Protection

### I.1 — ML-KEM Braid Protocol (SPQR)
| Item | Status | Notes |
|------|--------|-------|
| `braid.rs` library (chunking, handshake state) | ✅ | `protocol/src/braid.rs`: `split_key_to_chunks()` + `BraidHandshake` (5 tests pass) |
| `p2p/src/braid_handshake.rs` transport (stream/recv EK as chunks) | ✅ | `send_ek_braid`/`recv_ek_braid` + split-sink/stream variants; loopback test + client-wiring test pass (v0.3.16) |
| Wire protocol: `p2p-braid-chunk` frames + `ek_hash` integrity | ✅ | `BraidHandshake::add_chunk` verifies SHA-512 `ek_hash`, rejects dup/mismatch |
| **Chunked streaming wired into P2P handshake** | ✅ **Done (v0.3.16)** | `build_p2p_hello*`/`build_p2p_hello_ack*` advertise `braid:true`; `send_message` (initiator) + `handle_incoming_connection` (responder) exchange EK via braid, feed reconstructed key into ML-KEM KEM + Double Ratchet. Inline `kyber_enc_key` kept as fallback. |
| **Removed broken `crypto::BraidState` ct1/ct2 design** | ✅ **Removed (v0.3.16)** | The seed/ct1/ct2-reconciliation variant re-ran randomized `encapsulate` (two ct1 halves could never match) and had 0 consumers. SPQR now has exactly one correct implementation. |
| **Priority** | 🟢 | Latency optimization now live; no longer blocking |

### I.2 — Sealed Sender (Delivery Tokens)
| Item | Status | Notes |
|------|--------|-------|
| `delivery_tokens` library (HMAC-SHA256 HKDF) | ✅ | 258 lines, 5 tests |
| `DeliveryTokenMessage` wire format | ✅ | Defined + generated in client |
| Integration into client `send_message` | ✅ | Client sends `DeliveryTokenMessage` before each encrypted P2P message (B4) |
| Relay token verification | ✅ | Relay `RelayState` processes token messages (B4) |
| Token registration in DHT/routing space | ❌ | Spec says "Bob registers token in local P2P routing space" — still uses direct DHT |
| **Priority** | 🟡 | Token wiring (B4) done; DHT registration optional for first app |

### I.3 — PQ-Sender Keys (Group Messaging)
| Item | Status | Notes |
|------|--------|-------|
| ML-DSA-87 signing keypair | ❌ | No ML-DSA implementation |
| Sender Key bundle distribution | ❌ | No group key exchange |
| Group message fan-out (single encrypt + sign) | ❌ | No group messaging |
| Epoch reset on member removal | ❌ | No group management |
| **Priority** | 🟢 | Can defer; 1:1 messaging is first app focus |

### I.4 — PIR Contact Discovery
| Item | Status | Notes |
|------|--------|-------|
| `pir` library (blind registries, cuckoo hashing) | ✅ | 417 lines, 7 tests |
| Client-side `PirContactCache` for local blind lookups | ✅ | `PirContactCache::lookup()` provides privacy-preserving local contact discovery |
| PIR-over-DHT (`/pir-query` endpoint) | ✅ | DHT server dispatches `pir-query` (dht_node.rs:351) → `handle_pir_query`; client `pir_dht_lookup()` (`add send --pir`) issues PIR queries and processes responses |
| **Priority** | 🟡 | Local cache sufficient for first app; PIR-over-DHT is a hardening pass |

---

## PART II: Mobile, Bandwidth & Push Architecture

### II.1 — Edge-Core Architecture
| Item | Status | Notes |
|------|--------|-------|
| Core node (full routing) | ✅ | Relay exists (`relay/src/main.rs`) |
| Edge client (leaf-only mode) | ✅ | `NodeRole::Edge` with `allow_relay=false` |
| `--role core|edge` CLI flag | ✅ | Added to relay in v0.3.11 |
| `--network-state unrestricted|metered|tactical` | ✅ | Added to relay in v0.3.11 |
| **Multi-relay failover** | ✅ | `select_fastest_relay()` parallel probe, `relay_fetch_all()` parallel fetch + deduplication |
| **Multi-bootstrap registration** | ✅ | `register-all-bootstraps` parallel PoW, `check-register` parallel status check |
| **Priority** | ✅ | **COMPLETE** - Edge-Core implemented in v0.3.11 |

### II.2 — Adaptive Traffic Budgeting
| Item | Status | Notes |
|------|--------|-------|
| OS network state detection | ⚠️ Partial | `NetworkState` enum with 3 tiers; CLI flag available, no auto-detection |
| `TrafficBudget` per network state | ✅ | `TrafficBudget` struct with rates, burst multipliers, mixnet/push toggles |
| CBNP rate adaptation based on network | ✅ | `lambda_seconds`, `base_rate_pps`, `burst_multiplier` per state |
| **Priority** | 🟡 | Desktop-first; auto-detection later |

### II.3 — PQ Push Notifications
| Item | Status | Notes |
|------|--------|-------|
| Push proxy selection | ❌ | No push proxy client |
| Blinded push token generation | ❌ | No blinded tokens |
| Push proxy notification flow | ❌ | No PQ-PPN |
| **Priority** | 🟢 | Desktop doesn't need push; mobile follow-up |

### II.4 — State-Compressed Braiding
| Item | Status | Notes |
|------|--------|-------|
| Pre-computed seed caching | ❌ | No seed cache |
| Ratchet slow-down on cellular | ❌ | No adaptive ratchet interval |
| **Priority** | 🟢 | Optimization for mobile data; not blocking |

---

## PART III: Local Data-at-Rest Protection

### III.1 — Hardware-Bound Key Hierarchy
| Item | Status | Notes |
|------|--------|-------|
| HSM/TEE key generation (stub) | ✅ | `RootSecretSource::Hsm` stub ready for platform integration |
| User entropy (passcode) | ✅ | `RootSecret::from_passphrase()` with Argon2id |
| HKDF-SHA-512 key combination | ✅ | `IdentityRootKey::derive()` + `derive_session_keys()` |
| Per-session key separation | ✅ | Ratchet root, CBNP cover, sealed sender, delivery token, auth HMAC |
| **Priority** | ✅ | **COMPLETE** - Hardware-bound hierarchy in v0.3.11 |

### III.2 — Database Encryption at Rest
| Item | Status | Notes |
|------|--------|-------|
| SQLite database (sqlx) | ✅ | Client uses `messages.db` |
| AES-256-GCM enforcement | ✅ | Application-level encryption in `MessageStore` (B3); key at `.add/db_key.json` (0o600) |
| Page-level nonce randomization | ⚠️ Partial | AES-GCM per-row; no SQLCipher-style page randomization |
| In-memory ephemeral DB | ✅ | `MessageStore::open_in_memory()` — `sqlite::memory:` with fresh random key; `kem_sessions` table for KEM handshake state |
| **Priority** | 🟡 | Application-level encryption sufficient for v1; page randomization defer |

### III.3 — Ephemeral Memory / Biometric Gates
| Item | Status | Notes |
|------|--------|-------|
| `secure_zero_memory` + `mlock` | ✅ | `secure_mem.rs` with volatile writes + `GuardedKeyMaterial` |
| `secure_zero_memory_hardened` (speculation barriers) | ✅ | LFENCE/DSB+ISB barriers in v0.3.11 |
| Active memory shredding on background | ✅ | SIGINT lifecycle hooks (I2) zeroize and exit cleanly |
| Biometric gate | ❌ | No biometric re-validation (desktop-only; mobile later) |
| **Priority** | ✅ | mlock + guard pages + speculation barriers + lifecycle hooks sufficient for v1 |

### III.4 — Anti-Forensic Rollback
| Item | Status | Notes |
|------|--------|-------|
| Snapshot-resistant key custody (SSS 2-of-3 + mlock + MADV_DONTDUMP) | ✅ **Done (v0.3.16b)** | `crypto/src/snapshot_defense.rs`: `VolatileKey`/`Shard`/`PinnedBytes` pin key+shards+identity to RAM, exclude from core dumps, zeroize on drop; `split_key`/`reconstruct` over GF(2^8); `verify_ephemeral_mount` + `enforce_ephemeral_storage` (panic on non-tmpfs when `ADD_REQUIRE_TMPFS=1`); `SecKit` wires generate→split→persist (3 OHT dirs, fetch-and-delete)→recover-from-any-2 at daemon boot. Wired into `bootstrap`/`relay` `main`. 9 tests pass (+ `seckit_bootstrap_then_recover_roundtrip`); live binary smoke-tested (3 shards written, restart + 1-shard-loss recover). |
| Lattice key blinding (secret sharing) | ❌ | No additive masking of ML-DSA keys (SSS here covers payload keys, not identity-key blinding) |
| Hardware monotonic counter binding | ❌ | No hardware counter |
| State-destruct on clone detection | ❌ | No clone detection (tmpfs enforcement mitigates offline disk clone) |
| **Priority** | 🟡 | SSS + ephemeral-mount enforcement done; hardware-counter binding deferred |

---

## PART IV: Network Resilience & Infrastructure

### IV.1 — DPI Evasion / Pluggable Transports
| Item | Status | Notes |
|------|--------|-------|
| TLS/WebSocket encapsulation | ✅ | Relay uses `wss://` (TLS) |
| Traffic camouflage (looks like HTTPS) | ❌ | WebSocket upgrade reveals protocol |
| Obfuscation layer (obfs4-style) | ❌ | No pluggable transport |
| **Priority** | 🟢 | TLS + WebSocket sufficient for first app |

### IV.2 — Certificate-Based Core Node Admission
| Item | Status | Notes |
|------|--------|-------|
| Web of Trust cert management | ❌ | No WoT cert management (defer to v2) |
| Core node certificate validation | ✅ | TOFU pinning: relay `known_peers` in `RelayState` (I1); auto-accept first-seen, reject unknown |
| Sequoia-based cert verification | ✅ | Sequoia available in workspace |
| **Priority** | 🟡 | TOFU sufficient for v1; full WoT later |

### IV.3 — Headless Daemon
| Item | Status | Notes |
|------|--------|-------|
| CLI-native headless operation | ✅ | `add` binary is CLI-only |
| No GUI dependencies | ✅ | Rust CLI with clap |
| **Priority** | ✅ | Already done |

### IV.4 — OHT Extensions (Large Payload)
| Item | Status | Notes |
|------|--------|-------|
| Oblivious Hash Table implementation | ❌ | No OHT |
| Large file chunking + distribution | ❌ | No large payload handling |
| AES key + chunk manifest separation | ❌ | No manifest layer |
| **Priority** | 🟢 | Text-first; file transfer in follow-up |

---

## PART V: Real-World Implementation Defenses

### V.1 — CBNP
| Item | Status | Notes |
|------|--------|-------|
| `cbnp` library (Poisson-timed cover traffic) | ✅ | 383 lines, 6 tests |
| Integration into relay/p2p transport | ✅ | Wired into relay background task (B2); `--cbnp-enabled` CLI flag |
| Continuous dummy loops on Core Nodes | ✅ | Relay spawns CBNP task generating cover packets at Poisson intervals |
| **CBNP on federation channels** | ✅ | Cover packets sent after real messages on peer-to-peer relay connections (obscures timing correlation) |
| **Mix routing delays** | ✅ | Core relays apply random 1-60s delays on relay-forward (ACS2.6 §V.4) |
| **Global epoch synchronization** | ✅ | All nodes align to 2024-01-01 UTC reference epoch |
| **Coordinator beacons** | ✅ | `is_coordinator` flag for timing beacon broadcast |
| **Slot-aligned cover traffic** | ✅ | ±10% jitter within coordinated slots |
| Volume anchoring based on peer count | ❌ | No dynamic scaling; fixed λ |
| **Priority** | ✅ | **COMPLETE** - Full CBNP coordination in v0. v0.3.11 |

### V.2 — OMAP Pipelining & Bloom Filters
| Item | Status | Notes |
|------|--------|-------|
| Bloom filter implementation | ❌ | No bloom filter |
| Parallel batch lookups | ❌ | No pipelined queries |
| Delta sync with OHT storage | ❌ | No delta sync |
| **Priority** | 🟢 | Optimization for scale; not blocking first app |

### V.3 — Guard Pages / Memory Hardening
| Item | Status | Notes |
|------|--------|-------|
| `mlock` memory locking | ✅ | Implemented in `secure_mem.rs` |
| `secure_zero_memory` (volatile + fence) | ✅ | DSE-resistant |
| `secure_zero_memory_hardened` (speculation barriers) | ✅ | LFENCE/DSB+ISB in v0.3.11 |
| Virtual guard pages (`mmap` + `PROT_NONE`) | ✅ | `GuardedKeyMaterial` (B1); buffer overflows trigger SIGSEGV |
| **Priority** | ✅ | **COMPLETE** - Full hardening in v0.3.11 |

### V.4 — Native Lifecycle Integrations
| Item | Status | Notes |
|------|--------|-------|
| Android `onTrimMemory` hook | ❌ | No JNI/Kotlin code |
| iOS `didEnterBackground` hook | ❌ | No Swift code |
| **Priority** | 🟢 | Desktop-only first app |

---

## PART VI: Sovereign Infrastructure

### VI.1 — Confidential Computing / Attestation
| Item | Status | Notes |
|------|--------|-------|
| SEV-SNP / TDX attestation | ❌ | No confidential computing |
| `REPORT_DATA` binding | ❌ | No hardware report |
| VCEK certificate verification | ❌ | No cert verification |
| TCB invalidation lifecycle | ❌ | No 6-hour cert rotation |
| **Priority** | 🟢 | Server-side infrastructure; client doesn't need this |

### VI.2 — Jurisdictional Splitting
| Item | Status | Notes |
|------|--------|-------|
| Geolocation-aware routing | ❌ | No geo-IP awareness |
| Jurisdiction diversity enforcement | ❌ | No jurisdictional rules |
| WireGuard mesh tunnels | ❌ | No WireGuard integration |
| **Priority** | 🟢 | Multi-relay feature; not blocking first app |

---

## First App Priority Worklist

### 🔴 Blockers (must have) — ALL RESOLVED

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | **Wire delivery tokens into client send flow** | ✅ Done | Client sends `DeliveryTokenMessage` before encrypted P2P (B4) |
| 2 | **Wire PIR into DHT contact lookup** | ✅ Done | `PirContactCache` in client provides blind local lookups (B5) |
| 3 | **Wire CBNP into relay as background task** | ✅ Done | `CbnpSession` in relay background task (B2) |
| 4 | **Database encryption at rest** | ✅ Done | Application-level AES-256-GCM in `MessageStore` (B3) |
| 5 | **Guard pages for key memory** | ✅ Done | `GuardedKeyMaterial` with mmap PROT_NONE pages (B1) |

### 🔐 Bidirectional E2E Encryption (Ratchet) — RESOLVED in v0.3.9

| # | Task | Status | Notes |
|---|------|--------|-------|
| E1 | **Initiator can decrypt responder's reply** | ✅ Resolved (v0.3.9) | Wire format fix: `encrypt_message` now puts 2-byte Kyber CT length AFTER kyber_ct (not before), matching what `decrypt_message` expects |
| E2 | **Responder can decrypt follow-up messages from initiator** | ✅ Resolved (v0.3.9) | Symmetric ratchet step on receive direction works after initial DH ratchet |
| E3 | **Out-of-order message handling (skip message keys)** | ✅ Resolved (v0.3.9) | `skip_message_keys` buffer correctly stores chain keys for gaps up to N=1000 |
| E4 | **Double Ratchet state synchronization** | ✅ Resolved (v0.3.9) | Both parties maintain consistent `root_key`, `chain_key_send`, `chain_key_recv`, `dh_ratchet_key_pair` |
| E5 | **E2E encrypted round-trip in integration test** | ✅ Resolved (v0.3.9) | `test_bidirectional_ratchet_roundtrip` passes: 4-message round-trip (initiator→responder→initiator→responder) with Kyber-mixed decryption on all subsequent messages |

> **v0.3.9 fix summary:** The root cause was a wire format mismatch in `encrypt_message()` vs `decrypt_message()`. The sender wrote `nonce + aes_ct + 2-byte-len + kyber_ct` but the receiver read the 2-byte length from the END of the body. Since the last 2 bytes of the Kyber ciphertext are effectively random, `kyber_len` was always wrong, causing the receiver to fall back to `simple_decrypt` which doesn't mix in the Kyber shared secret — resulting in AES-GCM decryption failure. Fixed by moving the 2-byte length to the end: `nonce + aes_ct + kyber_ct + 2-byte-len`.

---

### 🟡 Important (should have for first app)

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6 | **TOFU certificate-based admission** | ✅ Done | TOFU pinning in relay `RelayState` (I1); reject unknown fingerprints |
| 7 | **Braid protocol integration** | ✅ Done (v0.3.16) | `p2p/src/braid_handshake.rs` wired into `send_message` + `handle_incoming_connection`; broken `crypto::BraidState` removed |
| 8 | **Wire lifecycle memory hooks** | ✅ Done | SIGINT handler in client + relay (I2); graceful shutdown with clean exit |
| 9 | **PIR-over-DHT endpoint** | ✅ Done | DHT `pir-query` dispatch + client `pir_dht_lookup()` wired; `add send --pir` |
| 10 | **Cross-relay delete propagation** | ✅ Done | `forward_delete_request` propagates read receipts across federation |

### 🟢 Can defer (v2.6 follow-up)

| # | Task | Effort | Notes |
|---|------|--------|-------|
| 11 | PQ-Sender Keys (group messaging) | Very High | Needs ML-DSA-87, group management, epoch reset |
| 12 | Anti-forensic rollback | High | Needs hardware monotonic counter |
| 13 | OHT / large payload handling | High | Needs OHT distributed storage |
| 14 | Bloom filter delta sync | Medium | Optimization for mailbox polling |
| 15 | Jurisdictional splitting | Medium | Needs geo-IP database + routing rules |
| 16 | Confidential computing | Very High | Server-side; SEV-SNP/TDX platform needed |
| 17 | Mobile push notifications | High | Needs APNs/FCM integration |
| 18 | Adaptive traffic budgeting auto-detection | Medium | Mobile-only; needs OS network state API |
| 19 | WoT certificate management | High | Decentralized trust infrastructure |
| 20 | Obfuscation transports (obfs4) | Medium | Pluggable transport layer |
| 21 | Page-level nonce randomization (SQLCipher) | Medium | Database hardening |
| 22 | Dynamic CBNP volume anchoring | Medium | Scale cover traffic with active peer count |
| 23 | Debian package build system | 📦 Done | cargo-deb metadata in Cargo.toml, debian/ dirs, Makefile targets |
| 24 | Reflector Bot package | ✅ Done | add-bot crate with echo functionality |

---

## Summary

**ACS2.6 Compliance: 11/11 Core Requirements Implemented**

| Spec Section | Feature | Status |
|--------------|---------|--------|
| **Part I.1** | ML-KEM-1024 Braid (SPQR) | ✅ Complete (v0.3.16 wired + broken ct1/ct2 removed) |
| **Part I.1** | Relayed Status (☑️) | ✅ Complete |
| **Part I.1** | Sender Polling | ✅ Complete |
| **Part I.1** | Checkmarks (🔘☑️✔️✔️✔️) | ✅ Complete |
| **Part I.2** | Sealed Sender + 96-bit Tokens | ✅ Complete |
| **Part II.1** | Edge-Core Architecture | ✅ Complete |
| **Part III.1** | Hardware-Bound Keys | ✅ Complete |
| **Part III.2** | Message History Ledger | ✅ Complete |
| **Part V.1** | CBNP Coordination | ✅ Complete |
| **Part V.3** | Hardened Subspaces | ✅ Complete |
| **Part V.4** | Cross-Relay Deletion | ✅ Complete |

**Implemented and wired:** 11/11 core ACS2.6 requirements
**Library exists, not integrated:** 0 (none remaining)
**Partially implemented:** 4 items (III.2 page-level nonce randomization, II.2 OS network-state auto-detection, IV.1 traffic camouflage/obfs4, IV.2 full WoT cert management)
**Not implemented:** the v2.6 follow-up set below (group messaging, anti-forensic rollback, OHT, Bloom filters, jurisdictional splitting, confidential computing, mobile push, adaptive budgeting auto-detection, WoT certs, obfuscation transports, mobile memory shredding, biometric gates, SQLCipher page encryption, dynamic CBNP scaling)

**Completed 2026-06-25 (v0.3.0-v0.3.10):**
1. ✅ Guard pages (B1) — `GuardedKeyMaterial` with mmap PROT_NONE
2. ✅ CBNP background task in relay (B2) — Poisson-timed cover traffic
3. ✅ Database encryption (B3) — AES-256-GCM application-level encryption
4. ✅ Delivery token wiring (B4) — HMAC-SHA256 tokens in send flow
5. ✅ PIR contact discovery (B5) — `PirContactCache` local blind registry
6. ✅ TOFU cert admission (I1) — Relay peer fingerprint pinning
7. ✅ Lifecycle memory hooks (I2) — SIGINT graceful shutdown
8. ⚠️ Braid protocol — Library exists, optional for v1

**Completed 2026-07-05 (v0.3.11):**
9. ✅ Hardware-bound key hierarchy (III.1) — Argon2id + HKDF-SHA512 with HSM stub
10. ✅ Edge-Core architecture (II.1) — NodeRole, NetworkState, TrafficBudget, CLI flags
11. ✅ CBNP coordination (V.1) — Global epoch sync, coordinator beacons, slot-aligned cover
12. ✅ Hardened subspaces (V.3) — LFENCE/DSB+ISB speculation barriers, hardened zeroing

**Remaining deferred items (v2.6 follow-up):** PQ-Sender Keys (group messaging), Anti-forensic rollback, OHT / large payload handling, Bloom filter delta sync, Jurisdictional splitting, Confidential computing, Mobile push, Adaptive budgeting auto-detection, WoT certs, Obfuscation transports, Memory shredding on mobile, Biometric gates, Page-level DB encryption (SQLCipher), Dynamic CBNP scaling

**Completed 2026-07-06 (Reflector Bot):**
23. ✅ Reflector Bot — Headless echo bot with TTL inheritance, loop prevention, zero-footprint storage
24. ✅ Default contact integration — `NN-B0T-REFL` auto-added in CLI and desktop UI

**Completed 2026-07-09 (v0.3.16 — SPQR Braid fully wired):**
25. ✅ SPQR Braid wired into live P2P handshake + ratchet — `p2p/src/braid_handshake.rs` streams the 1568B ML-KEM-1024 EK as `p2p-braid-chunk` frames; `send_message` + `handle_incoming_connection` negotiate `braid:true` and feed the reassembled key into KEM + Double Ratchet. Inline `kyber_enc_key` kept as fallback.
26. ✅ Removed broken `crypto::BraidState` ct1/ct2 design — re-ran randomized `encapsulate` during reconciliation (could never match) and had 0 consumers. SPQR now has one correct implementation.
