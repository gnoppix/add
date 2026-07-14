# Add — Address Discovery & Routing Design

This document describes how Add locates peers for direct P2P messaging, the
current production mechanism, its threat model, and the planned hardened
replacement ("contact-book" discovery). It is paired with `SECURITY.md`.

---

## 1. Goals

- Let Alice discover Bob's P2P endpoint (`ws://<ip>:<port>`) so she can open a
  direct, post-quantum, forward-secret channel.
- Keep the bootstrap/routing infrastructure stateless enough to run on cheap,
  untrusted hosts.
- Never let the routing infrastructure read message contents (already true
  today — messages are E2E encrypted).
- **Target (not yet shipped):** also hide *who is where* (IP↔ID mapping) and
  the *contact graph* from the infrastructure itself.
- **Decision (2026-07):** drop the earlier "3-server sharded + composition
  server" sketch. Trust comes from out-of-band **fingerprint verification**,
  not from server count. The cert store and the address store are each a
  single, opaque, content-addressed server; the server is never trusted.

---

## 2. Current mechanism — open DHT

### 2.1 What is stored

On startup, `add listen` computes the advertised address via NAT traversal
(UPnP/IGD, else STUN) and calls `dht_register_addr_record_all`, which writes an
`addr_record` to **all three bootstrap servers** (`bootstrap-us/eu/asia`).

Each row in the bootstrap `kv_store` (`sqlite`) contains, in **plaintext**:

| Field          | Example                         | Meaning                         |
|----------------|---------------------------------|---------------------------------|
| `key`          | `addr:NN-iQF7-R3XO`             | the user's Null ID (pseudonym)  |
| `value`        | `ws://185.70.184.239:42887`     | public IP + listener port       |
| `publisher_fp` | `<ml-dsa fingerprint>`          | owner's signing key fingerprint |
| `sig`          | ML-DSA-87 signature             | over `{null_id}|{address}|{ttl}`|
| `salt`, `seq`, `stored_at`, `expires_at`, `nonce` | — | bookkeeping / PoW / TTL |

The address is **not** encrypted before it reaches the DHT. The `sig` proves
ownership (only the key holder can publish), but the value itself is readable
by anyone with DB access.

### 2.2 Lifetime

- TTL = 3600s (1h). A running listener refreshes it; on public-IP change it
  re-registers; on port-only churn (symmetric NAT) it refreshes TTL without
  burning PoW.
- On stop, the record lingers up to 1h then expires. Restart re-registers and
  overwrites with the current address.
- Lookups (`dht_lookup`) are open: anyone who knows a Null ID can fetch its
  address record. This is a **public phone book**.

### 2.3 Servers

```
bootstrap-us.gnoppix.org   (host "me")     → wss://…/ws
bootstrap-eu.gnoppix.org   (host "is")     → wss://…/ws
bootstrap-asia.gnoppix.org (host "jp")     → wss://…/ws
relay-us/eu/asia.gnoppix.org               → message-delivery fallback only
```

DNS SRV discovery (`_add-bootstrap._tcp.gnoppix.org`) is attempted and falls
back to the hardcoded list above (no SRV records currently published).

### 2.4 Properties

- ✅ Message bodies never touch the bootstrap (E2E, post-quantum).
- ✅ Open discovery enables first contact with strangers.
- ❌ Bootstrap operator / host / anyone reading `kv_store` sees
      `Null ID → public IP : port` for every online user.
- ❌ No protection against a single compromised/bootstrap host harvesting the
      full ID↔IP map.

---

## 3. Threat model (current)

| Adversary                         | Sees IP↔ID? | Sees messages? | Sees contact graph? |
|-----------------------------------|-------------|----------------|---------------------|
| Passive network observer          | no*         | no             | no                  |
| Bootstrap server operator (root)  | **yes**     | no             | **yes** (all edges) |
| Hosting provider / VM snapshot    | **yes**     | no             | **yes**             |
| State subpoena of all 3 servers   | **yes**     | no             | **yes**             |
| Compromised client                | (has own)   | (has own)      | (has own)           |

\* unless correlation via relay timing; see §5.4.

---

## 4. Proposed mechanism — "contact-book" discovery

Replace the open DHT with a **closed, encrypted, sharded** address store. The
design below is the *recommended* form that closes the holes identified in
`SECURITY.md` §2.

### 4.1 Principles

1. **The server must never be able to decrypt.** Address records are encrypted
   under the *contact's* public key on the client, before they leave the
   device. The server is a dumb opaque blob store.
2. **No access-control list, no composition server.** Records are addressed by
   content hash, not by a server-held mapping. The server learns no
   ID↔shard↔contact edges.
3. **Erasure coding, not strict 3-of-3.** Use `k-of-n` (e.g. any 2-of-3) so one
   unavailable server doesn't break discovery.
4. **Signed shards.** Each shard carries an ML-DSA signature; clients verify on
   reassembly (defends against poisoned/unavailable shards).
5. **Single opaque server, not a shard quorum.** The earlier "distribute +
   shard + composition server" sketch is **dropped**. Instead: one dumb,
   content-addressed blob store per dataset (one for certs, one for encrypted
   address records). The server is never trusted — correctness comes from
   signatures + out-of-band fingerprint verification, not from server count.
   (Diverse operators remain a bonus for availability, not a trust root.)

### 4.2 Public-key / certificate store (the onboarding path)

There is **no** plaintext public-key directory keyed by Null ID. Instead:

- Each user publishes their **ML-DSA cert + ML-KEM public key**, content-
  addressed by `H(pubkey)` (or by the fingerprint itself), to a single opaque
  store. The server stores a blob + signature; it holds no ID↔key mapping it
  can meaningfully mutate into a trusted statement.
- Trust anchor = the **fingerprint Bob speaks out-of-band**.

**Onboarding flow (chosen UX):**
1. Bob (on a call with Alice) says: "my ID is `NN-XXXX` and my fingerprint is
   `ABCDE`." (ID + fingerprint exchanged verbally / out-of-band.)
2. Alice types Bob's **ID + fingerprint** into her client.
3. Client pulls Bob's public cert from the store, addressed by ID.
4. Client hashes the downloaded cert and **compares to the fingerprint Bob
   spoke**. Match ⇒ cert authentic; mismatch ⇒ reject + warn.
5. On success, cert is cached locally as *verified*; further resolves use the
   cache, not the server.

**Why this is sound:** the server is only a transport for the cert. A malicious
server returning a wrong key fails step 4 (collision-resistant hash + ML-DSA —
it cannot forge a cert hashing to Bob's fingerprint). No server trust required.

**Hardening notes:**
- Address the cert by `H(pubkey)`/fingerprint, not by the mutable Null ID, so
  the server cannot even swap "ID→cert" mappings.
- Encode the fingerprint as a grouped, checksummed string (base32 groups-of-4
  + checksum word, Signal-safety-number style) so read-aloud / typed typos
  fail loudly. Prefer paste/scan over manual entry.
- Show a "both sides confirm the SAME fingerprint" screen and, optionally, a
  derived safety number compared on the call (Signal model) — this is TOFU +
  out-of-band confirmation, not "server vouches."
- If a cached cert is re-pulled (key rotation), re-verify and alert on change;
  rotations must be re-confirmed out-of-band.
- Caveat to state to users: if Alice types the fingerprint wrong, she matches
  against her own typo. Safe-encoding + visible same-fingerprint confirmation
  mitigate this.

### 4.3 Address record store (replaces open DHT)

Same opaque-store pattern as the cert store, but the value is the encrypted
address record:

Publish: build `R = {null_id, ws://<ip>:<port>, ttl}`; encrypt `R` under a key
**derived from Bob's public ML-KEM key** (chicken-and-egg avoided — decryption
key is Bob's *public* key, already held post-onboarding); content-address the
ciphertext blob; sign it.

Resolve: any contact holding Alice's public key fetches the blob by hash,
verifies the signature, decrypts with their private ML-KEM key → `R` →
`ws://<ip>:<port>`. **The server sees only a ciphertext blob addressed by
hash — no IP, no Null ID, no contact edge.**

This closes the holes in the old shard sketch (no composition server = no
correlation oracle; opaque hash-addressed blobs = no ID↔shard mapping; no ACL
= no contact-graph leak).

### 4.4 Remaining leak — traffic analysis

Even with encrypted shards, a server observing *Alice fetches hashes X then
connects to IP Y with matching timing/size* can infer the link. Full
resistance needs **PIR** (private information retrieval — `handle_pir_query`
is already scaffolded in `dht-core`) or cover traffic. Documented, not yet
closed.

### 4.5 Product trade-off

Closed discovery means **no open first contact with strangers** — you must
import the peer's key out-of-band first (which Add already requires: import +
fingerprint verify). This is a deliberate constraint, consistent with the
"authenticated contacts only" model, and should be stated plainly to users.

---

## 5. Reference — current crypto stack

| Layer            | Primitive (FIPS)        | Crate / impl                          |
|------------------|-------------------------|---------------------------------------|
| KEM (key agree)  | ML-KEM-1024 (203)       | `ml-kem` 0.3                          |
| Signatures       | ML-DSA-87 (204)         | `sequoia-openpgp` / `pqcrypto-dilithium` |
| Session          | Double Ratchet          | AES-256-GCM per frame, forward secret |
| Transport        | `ws://` (direct P2P)    | app-layer encrypted; `wss://` on relay|
| PoW              | difficulty-8 addr record| nonce-log replay protection           |

No system GnuPG binary; all crypto is in-process Rust.

---

## 6. Open questions / TODO

- [ ] Specify cert-store + address-store blob format and ML-KEM-based KDF precisely.
- [ ] Decide fingerprint encoding (base32 groups-of-4 + checksum word) and
      same-fingerprint confirmation UI.
- [ ] Wire PIR for query hiding on the address store (build on `handle_pir_query`).
- [ ] Decide TTL/refresh policy for the encrypted address record.
- [ ] Publish `_add-bootstrap` / `_add-relay` SRV records (currently unused).
- [ ] Publish `_add-bootstrap` / `_add-relay` SRV records (currently unused).
