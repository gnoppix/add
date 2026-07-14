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
5. **Diverse operators.** The privacy gain only holds if the `n` servers are
   run by independent parties / jurisdictions. Co-located servers gain little.

### 4.2 Record lifecycle

Alice wants Bob reachable. Alice already holds Bob's ML-KEM public key + ML-DSA
cert (out-of-band import + fingerprint verify — the same flow used to start a
conversation today).

Publish (Alice, on Bob's behalf — or Bob publishes for himself):
1. Build plaintext address record `R = {null_id, ws://<ip>:<port>, ttl}`.
2. Encrypt `R` under a key **derived from Bob's public ML-KEM key** → `C`.
   (Chicken-and-egg avoided: the decryption key is Bob's *public* key, which
   Alice already has post-import. No prior session required.)
3. Erasure-encode `C` into `n` shards `{s₁..sₙ}` with `k`-reconstruct.
4. For each shard, compute `hᵢ = H(sᵢ)`, sign `sᵢ` with Alice's ML-DSA key.
5. PUT each `(hᵢ, sᵢ, sig)` to a different server (content-addressed; server
   stores no key↔shard mapping).

Resolve (Bob, or any contact holding Alice's public key):
1. From Alice's Null ID + Bob's own key, derive the same set of shard hashes
   `hᵢ` (deterministic). Fetch any `k` of them from the `n` servers.
2. Verify each shard signature; erasure-decode to `C`; decrypt `C` using Bob's
   **private** ML-KEM key → `R` → `ws://<ip>:<port>`.

Result: only contacts holding the right public key can resolve and decrypt;
**the server sees only ciphertext blobs addressed by hash.**

### 4.3 Why this beats the "3-server + composition server" sketch

- The original sketch put "how shards compose" on server 3 → that server
  becomes the correlation oracle (it learns which A-shard + B-shard = one
  record). Content-addressed erasure coding removes that server entirely.
- The original sketch accepted "server knows Alice↔Bob edge." With opaque
  hash-addressed blobs and no ACL, the server learns neither the edge nor the
  IP nor the Null ID.

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

- [ ] Decide `k`, `n`, and operator diversity model for sharded store.
- [ ] Specify shard format + key derivation (ML-KEM-based KDF) precisely.
- [ ] Wire PIR for query hiding (build on `handle_pir_query`).
- [ ] Decide TTL/refresh policy under the closed model.
- [ ] Publish `_add-bootstrap` / `_add-relay` SRV records (currently unused).
