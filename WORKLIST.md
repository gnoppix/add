# ACS2.6 Roadmap Worklist

## Part I: Metadata Confidentiality (TIER 0+1 → TIER 2)

### ✅ COMPLETED
- [x] Post-Quantum Crypto: ML-DSA-87 signing, ML-KEM-1024 encapsulation
- [x] Identity System: NID + GPG Fingerprint + PQ Fingerprint
- [x] Certificate Publishing to DHT (all 3 bootstrap servers)
- [x] Relay Delivery with Sealed Sender Tier 0 (anonymous sender_nid)
- [x] Double Ratchet Session Management
- [x] P2P WebSocket Listener with NAT traversal
- [x] Contact Management (add-contact, contacts.json)
- [x] End-to-End Send/Read via Relay
- [x] Startup Passphrase Dialog (Desktop UI) - in-memory only, clears on quit
- [x] fetch-cert accepts both GPG (40-char) and PQ (64-char) fingerprints
- [x] add-contact auto-resolves GPG FP → PQ FP via DHT lookup
- [x] Cert store publishes under both `cert:SHA256(PQ_FP)` and `cert:SHA256(GPG_FP)` keys
- [x] lookup_kyber_for_nid resolves GPG FP → PQ FP for KEM delivery
- [x] Version bump: Rust 0.3.26, Desktop 0.2.17
- [x] All 3 regions deployed at 0.3.26

### 🔧 IMMEDIATE FIXES (Quick Wins)

#### 1. Fix `fetch-cert` Fingerprint Verification Mismatch
**Status:** ✅ **DONE** — `Commands::FetchCert` now accepts both fingerprint types and verifies against the correct one (GPG FP → GPG FP, PQ FP → PQ FP from VK)

#### 2. Auto-Resolve PQ Fingerprint in `add-contact`
**Status:** ✅ **DONE** — `Commands::AddContact` calls `dht_fetch_cert_blind` with GPG FP, extracts PQ FP from returned VK, stores PQ FP in contacts

#### 3. Cert Store Key Consistency
**Status:** ✅ **DONE** — `dht_publish_cert` now publishes cert blob under BOTH keys:
- `cert:SHA256(PQ_FP)` (primary)
- `cert:SHA256(GPG_FP)` (for GPG-based lookups)
- `lookup_kyber_for_nid` resolves GPG FP → PQ FP before KEM lookup

### 📦 TIER 1: Timing Bucket Delivery (Part I.2)
- [ ] Implement timing bucket batching in relay (`add-relay/src/`)
- [ ] Configurable bucket interval (default 30-60s)
- [ ] Client-side batch submission API
- [ ] Relay-side bucket flushing with constant-rate cover traffic

### 📦 TIER 2: Private Information Retrieval (PIR) (Part I.2)
- [ ] PIR protocol implementation (`add-dht-core` or new crate)
- [ ] Cuckoo hashing + XOR-based PIR for cert/address lookups
- [ ] Bootstrap server `/pir-query` WebSocket endpoint
- [ ] Client-side PIR query generation in `dht_fetch_cert_blind`
- [ ] Fallback to standard lookup if PIR not supported

### 📦 TIER 3: Hardware Attestation (Part I.3)
- [ ] SEV-SNP Attestation for relay/bootstrap binaries
- [ ] TDX Attestation for Intel platforms
- [ ] Measurement register (MR) policy for binary integrity
- [ ] Attestation verification in client bootstrap flow
- [ ] REPORT_DATA binding to TLS cert / identity

### 📦 TIER 4: Certificate Transparency / SCT Auditing (Part I.4)
- [ ] CT log submission for published certs
- [ ] SCT inclusion in cert bundle
- [ ] Client-side SCT verification on cert fetch
- [ ] Gossip-based CT consistency proofs

---

## Part II: Decentralized Routing & Mixnet (Part II)

### 📦 Mixnet Topology
- [ ] Vuvuzela-style mixnet node implementation
- [ ] Sphinx packet format for mixnet routing
- [ ] Cover traffic generation (Poisson process)
- [ ] Loop traffic for timing analysis resistance

### 📦 Private Contact Discovery (Part II.2)
- [ ] PIR-based contact list sync
- [ ] Bloom filter or PSI-based presence
- [ ] No metadata leakage to bootstrap/relay

### 📦 Petname / Offline Message Queue (Part II.3)
- [ ] Petname system for human-readable aliases
- [ ] Offline message queue with expiry
- [ ] Delivery receipts with deniability

---

## Part III: Advanced Cryptography (Part III)

### 📦 Post-Compromise Security (PCS)
- [ ] Epoch-based ratchet key rotation
- [ ] Continuous key agreement (CKA) integration
- [ ] Compromise detection & recovery

### 📦 Forward Secrecy Verification
- [ ] Formal verification of ratchet state machine
- [ ] Key erasure proofs

### 📦 Deniability
- [ ] Offline deniability (no long-term sigs on messages)
- [ ] Online deniability (MAC-based auth)
- [ ] Judicial deniability proofs

---

## Infrastructure & Operations

### ✅ DONE
- [x] Bootstrap servers: EU (is), US (me), Asia (jp)
- [x] Relay servers: EU (is), US (me), Asia (jp)
- [x] DNS SRV discovery (`_add-bootstrap._tcp`, `_add-relay._tcp`)
- [x] nginx TLS termination at edge, not in-daemon
- [x] systemd service management
- [x] rsync-based binary deployment
- [x] All 3 regions at v0.3.26

### ⚠️ KNOWN ISSUE
- **US Bootstrap (`me`)**: Database corruption (disk I/O errors, `no such table: kv_store` in logs). EU and Asia bootstraps healthy. US server needs DB recovery/rebuild before it can serve GPG-keyed cert lookups.

### 🔧 PENDING
- [ ] Health check endpoints with Prometheus metrics
- [ ] Automated failover for bootstrap/relay
- [ ] Log aggregation (Loki/ELK)
- [ ] Certificate rotation automation

---

## Priority Order for Next Session

1. **Fix `fetch-cert` verification** (30 min) - unblocks smooth cert verification
2. **Auto-resolve PQ FP in `add-contact`** (1 hr) - major UX improvement
3. **Implement PIR** (1-2 weeks) - core Part I.2 deliverable
4. **Timing buckets** (1 week) - Tier 1 sealed sender
5. **Hardware attestation** (2-3 weeks) - Part I.3

---

## Notes

- All TLS terminated at nginx edge - daemons run plaintext WebSocket on localhost:9001
- Binaries deployed to `/root/add/` on servers, `/usr/local/bin/` locally
- Passphrase handling: `ADD_DB_PASSPHRASE` env var supported in CLI
- Desktop UI caches passphrase in memory only (no disk persistence)
- Client never uses own SSL cert - all TLS built into binary
- TPM disabled by default (`--no-default-features`)