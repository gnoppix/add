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

## 2. Current mechanism — open DHT  *(RETIRED 2026-07-14 — V0 clean-cut rebase)*

> **Status:** the plaintext `addr:` record described below no longer exists. As of
> 2026-07-14 the `addr-record` handler was removed server-side (`dht_node.rs`) and
> `dht_register_addr_record*` was removed client-side. Discovery now uses the
> opaque blob store + per-contact **encrypted** presence blobs (see §4.3). The
> DBs on all three bootstraps were wiped. This section is kept only as a record
> of what was replaced.

### 2.1 What *was* stored

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
| Bootstrap server operator (root)  | **no**      | no             | **no**              |
| Hosting provider / VM snapshot    | **no**      | no             | **no**              |
| State subpoena of all 3 servers   | **no**      | no             | **no**              |
| Compromised client                | (has own)   | (has own)      | (has own)           |

\* unless correlation via relay timing; see §5.4.

> **Updated 2026-07-14 (V0 rebase):** the operator can no longer read IP↔ID or
> the contact graph. Presence is stored as per-contact ML-KEM-encrypted blobs
> (§4.3); the server holds only ciphertext. A root operator on a bootstrap can
> read the opaque blobs but cannot decrypt them without the per-pair
> decapsulation key, which only the two mutual contacts can derive. (Prior to
> this date the table read "yes" for the operator — that reflected the retired
> plaintext `addr:` record, §2.)

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
3. **Replication, not erasure coding.** Each opaque blob is written to **all**
   bootstrap servers (strict N-of-N write) and any one can answer a fetch
   (any-1-of-N read). This gives the availability goal without Reed-Solomon
   erasure coding — for ~300-byte blobs the extra complexity and a shard
   composition step would contradict principle 5 (no composition server). If a
   server is down, fetches/reads fall back to the others. (The earlier "k-of-n"
   sketch is therefore **not** used — dropped alongside the composition server.)
4. **Signed blobs.** Each blob carries an ML-DSA signature over `{key‖value}`;
   the server verifies `VK == publisher null_id` and clients re-verify on fetch
   (defends against a poisoned/unavailable blob — no reassembly step since
   there are no shards).
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

**Publish (when a user generates a new ID):**
1. On first run (or "New Identity"), the client generates the ML-DSA cert +
   ML-KEM keypair locally. The Null ID (`NN-…`) and the fingerprint are derived
   from this cert.
2. The client computes `fp = fingerprint(cert)` and
   `key = H(pubkey)` (content-addressing key).
3. It uploads `{cert, fp, sig}` to the opaque cert store, addressed by `key`,
   where `sig` is the client's ML-DSA signature over `{cert || fp}` (proves the
   publisher holds the private key; lets the store reject unsigned junk without
   trusting the publisher).
4. The server stores the blob + signature keyed by `key`. It learns the cert
   and fingerprint, but holds **no mutable ID↔key mapping** it can present as a
   trusted statement — resolution still requires the out-of-band fingerprint.
5. The user then shares their **ID + fingerprint** out-of-band (e.g. on a call)
   so contacts can fetch and verify (see Onboarding flow below).

Note: the server sees the public cert and fingerprint on upload — that is
unavoidable for a fetchable directory and is **not** a secrecy loss (public
keys are public). What the design avoids is the server learning *who is connected to
whom* or being able to substitute a key undetected (caught at verify time).

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

### 4.3 Address record store (replaces open DHT) — implemented as V2.2

Per-contact **encrypted** presence blobs stored in the same opaque blob store as
the cert store. For each mutual contact `C`, the publisher `A`:

1. Derives its own KEM keypair `dk_A` from `A.null_id` (HKDF-SHA256 of
   `Sha256(A.null_id)` with label `add-sealed-sender-kyber-seed`, expanded to
   64 bytes → `KyberKeypair::from_seed`). `C`'s KEM public key `ek_C` is derived
   identically from `C.null_id`, so both ends are reproducible at runtime — no
   on-disk secret store.
2. Encapsulates: `ct_C = encaps(ek_C)`, yielding a per-contact shared secret
   `ss` (ML-KEM-1024).
3. AES-256-GCM-seals the listener address under `ss`: `blob =
   base64(hex(ct_C)) '.' base64(nonce‖ct)`.
4. Stores under opaque key `presence:H(A.fp‖C.fp)` with an ML-DSA `sig` over
   `{key‖value}`; the server verifies `VK == A.null_id` and stores the
   ciphertext verbatim — it **never** parses the value as an address or learns
   the contact edge.

Resolve: `C` recomputes `presence:H(A.fp‖C.fp)`, fetches the blob, verifies the
sig, decapsulates `ct_C` with its own `dk_C` → `ss` → AES-opens the address.
**The server sees only a hash-addressed ciphertext blob: no IP, no Null ID, no
contact graph.** An outsider lacking `dk_C` derives a *different* `ss` and
fails to open the blob.

This closes the holes in the old shard sketch (no composition server = no
correlation oracle; opaque hash-addressed blobs = no ID↔shard mapping; no ACL
= no contact-graph leak). Code: `client/src/presence.rs`
(`publish_presence` / `fetch_presence`); verified by the
`presence_pair_kem_roundtrip` unit test and a live two-identity publish→fetch.

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
| PoW              | (retired) addr-record   | nonce-log PoW was on the deleted `addr:` write; presence blobs need no PoW |

No system GnuPG binary; all crypto is in-process Rust.

---

## 6. Contact-list gating (mutual consent)

No message, request, ping, presence probe, or key exchange may be sent to or
accepted from an ID that is not in the local contact list. Consent must be
**mutual**: if Bob added Alice but Alice did not add Bob, neither endpoint may
send to the other.

### 6.1 Enforcement (client-side, both directions)

- **Outbound:** the client refuses to transmit any frame to an ID `∉` its
  contact list.
- **Inbound:** the client refuses to process any frame from an ID `∉` its
  contact list (drops before decryption / ratchet work, so a non-contact
  cannot waste CPU or probe presence). This is what actually blocks Bob→Alice
  in the asymmetric-add scenario — Alice has no Bob entry, so she drops his
  inbound.
  *Implemented 2026-07-14:* `handle_incoming_connection` (client/src/main.rs)
  now gates on `load_contacts()` — a `p2p-hello` from a fingerprint not in the
  local contact list is rejected before signature verification / ratchet work.*
- Server-side allow-lists are explicitly NOT relied upon (a modified client
  could bypass them). The client itself is the enforcement point.

### 6.2 Coupling to the crypto

"Added to contact list" is equivalent to "holds the peer's cert + verified
fingerprint" (§4.2). Therefore a non-contact also cannot resolve the peer's
encrypted address blob (§4.3) — they lack the cert needed to derive the opaque
fetch key and to decrypt. The gating rule is defense-in-depth on top of the
address-store crypto, and additionally gates pings/requests (which the address
store alone does not).

### 6.3 Pings and presence

Pings/presence are treated as gated traffic: **no inbound processing from a
non-contact, including pings.** There is no presence-discovery probe of IDs not
in the list. A "pending / added-you" indicator is local UI state derived from
an inbound add request the client chose to surface — not a network probe, and
only ever shown for IDs the user has themselves added.

### 6.4 Add / remove lifecycle

- **Add:** after the §4.2 onboarding (ID + fingerprint + cert verify), the peer
  is entered in the contact list and the client begins publishing that peer's
  personalized address blob (§4.3).
- **Remove:** immediately disables send/receive to that ID and stops publishing
  the contact's personalized address blob; the peer can no longer resolve the
  user's address via that blob. (Key rotation on removal: see §4.2 hardening.)

### 6.5 Properties

- Unsolicited contact from strangers or one-sided contacts is impossible.
- The rule is client-enforced, so it survives a hostile/modified server.
- Trade-off: no open first contact — consistent with the authenticated-contacts
  model; first contact always begins with out-of-band key exchange.

---

## 7. Open questions / TODO

- [ ] Specify cert-store + address-store blob format and ML-KEM-based KDF precisely.
- [ ] Decide fingerprint encoding (base32 groups-of-4 + checksum word) and
      same-fingerprint confirmation UI.
- [ ] Wire PIR for query hiding on the address store (build on `handle_pir_query`).
- [ ] Decide TTL/refresh policy for the encrypted address record.
- [x] Specify mutual-consent enforcement: inbound drop-before-decrypt path
      (done 2026-07-14 — `handle_incoming_connection` gates on contact list);
      pending-add UI state and remove→stop-publish coupling remain TODO.
- [ ] Publish `_add-bootstrap` / `_add-relay` SRV records (currently unused).
