# Add — Security Model & Hardening Notes

Companion to `DESIGN.md`. Covers what an attacker / operator can actually see
today, the RAM/key-snapshot question, and the analysis of the proposed sharded
"contact-book" discovery.

---

## 1. What is encrypted, what is not (today)

| Data                       | Where            | Encrypted? | Who can read it            |
|----------------------------|------------------|------------|----------------------------|
| Message bodies             | client ↔ client  | **yes**    | only sender + recipient    |
| Channel (ratchet frames)   | in transit       | **yes**    | only the two peers         |
| Address record (`addr:`)   | bootstrap DHT    | **no**     | **anyone with DB access**  |
| Null ID / fingerprint      | bootstrap DHT    | **no**     | **anyone with DB access**  |
| Contact list / keys        | local only       | at rest*   | the device owner           |

\* local store is not currently at-rest encrypted; see §3.

**Bottom line:** message *content* is safe; the *routing metadata* (who is at
which IP) is **plaintext on the bootstrap servers.**

---

## 2. Can a system admin see IPs and IDs? — YES

Anyone with root on a bootstrap host can run:

```sql
sqlite3 /root/.add/bootstrap_dht.db
  "SELECT key, value, publisher_fp FROM kv_store
   WHERE key LIKE 'addr:%';"
```

and read, for every online user: Null ID, public IP, listener port, and GPG
fingerprint. This is inherent to open DHT discovery — the bootstrap must know
the mapping to answer lookups. The ID is a *pseudonym* (no name/email), but
IP + persistent pseudonym is still linkable metadata.

---

## 3. RAM / key-snapshot analysis (the real question)

**Premises in the proposal:**
- SQLite (SQLCipher) needs a password to open the routing table.
- That password lives in RAM.
- RAM can be snapshotted (VM suspend, hibernate, swap, core dump, live dump).

**Assessment:**

1. **DB-at-rest encryption (SQLCipher) only protects the file on disk.** It
   does *not* protect a live attacker:
   - A root user can read the `add-bootstrap` process memory directly and pull
     decrypted rows — bypassing the DB key entirely.
   - A VM snapshot / hibernate captures the key *and* the live decrypted pages.
   - Swap can leak the key or rows to disk.
   So SQLCipher raises the bar for disk theft, not for a competent live
   adversary on the host.

2. **Sharding across servers does not fix the live-memory problem** — each
   shard host still holds its shard in RAM to serve it. It *does* help
   at-rest: one confiscated disk yields only ciphertext. But the operator-of-
   all-3 (same jurisdiction / same owner) gets everything anyway.

3. **The only structural fix is: the server never holds the key or the
   plaintext.** Client-side encryption (§4 of `DESIGN.md`) means a server
   compromise yields only ciphertext blobs addressed by hash — no key, no
   mapping, no IP, no Null ID in clear.

**Conclusion:** RAM-snapshot risk is real and is *not* solved by a DB password.
It is solved by never putting decryptable data on the server.

---

## 4. Analysis of the proposed sharded design

Proposal recap: distribute the address info across servers, encrypt + shard it,
store shards randomly; a "third server" holds how the shards compose; clients
poll all three, reassemble, decrypt, learn the IP:port. Closed to authenticated
contacts only (not a public phone book).

### 4.1 Objections & resolutions

1. **Same-operator sharding buys little.** If all servers are Gnoppix-run
   (same jurisdiction), one subpoena/compromise gets all shards. Sharding only
   helps against a *single* server being hacked or its disk seized. → Use
   **diverse, independent operators** for real gain.

**DECISION (2026-07): the sharded + composition-server sketch is DROPPED.**
Replaced by a single opaque, content-addressed blob store per dataset (certs
and encrypted address records), where trust comes from signatures + out-of-band
fingerprint verification, NOT from server count. The points below explain why
the shard sketch was rejected; the adopted design is in `DESIGN.md` §4.

2. **The "composition server" is the weak link.** A server that knows how
   shards compose is a correlation oracle (it learns which A+B = one record).
   → Removed: **content-addressed opaque blobs**; no server holds the mapping.

3. **You can avoid even the contact-graph leak.** Conceding "server knows
   Alice↔Bob" is unnecessary. Make the store a **dumb opaque blob store**:
   encrypt each record under the *contact's* key, serve by content-hash, **no
   ACL**. The server then learns nothing — not the IP, not the Null ID, not
   the edge. Strictly stronger than an ACL model, and removes objection #2.

### 4.1 Onboarding via fingerprint (chosen UX)

The earlier objection "storing all public keys on the server builds a user
directory" still holds: a plaintext key directory keyed by Null ID lets the
server enumerate the whole roster and correlate it with address fetches. So
**no plaintext key directory**. Instead:

- Users publish certs content-addressed by `H(pubkey)` (or fingerprint) to a
  single opaque store. The server holds a blob + signature, no trusted ID↔key
  mapping.
- **Publish step (new-ID generation):** the client generates the ML-DSA cert +
  ML-KEM keypair locally, derives Null ID + fingerprint, signs
  `{cert || fingerprint}` with its own ML-DSA key, and uploads
  `{cert, fingerprint, sig}` addressed by `H(pubkey)`. The signed upload lets
  the store reject unsigned junk without trusting the publisher; the
  content-addressing key means the server cannot present a swapped "ID→cert"
  mapping as authoritative.
- On upload the server inevitably sees the **public** cert + fingerprint. That
  is not a secrecy loss (public keys are public) and is required for a
  fetchable directory. What it must NOT gain is a trusted ID↔key statement or
  the ability to substitute a key undetected — both are defeated at verify
  time by the out-of-band fingerprint.
- Onboarding: Bob speaks his **ID + fingerprint** out-of-band (e.g. on a call);
  Alice enters both; her client pulls the cert, hashes it, and **compares to
  Bob's spoken fingerprint**. Match ⇒ authentic; mismatch ⇒ reject. The server
  is only a transport — it cannot forge a cert hashing to Bob's fingerprint.
- Trust anchor is the out-of-band fingerprint, never the server. This is TOFU
  + out-of-band confirmation (Signal model), not "server vouches."
- Hardening: checksummed grouped fingerprint encoding (typos fail loudly);
  "both sides confirm the SAME fingerprint" screen; re-verify cached certs on
  rotation and alert on change; state the caveat that a mistyped fingerprint
  matches against the user's own typo.

**Why not a 3-server key store:** trust already derives from the fingerprint,
so adding servers adds moving parts without raising the bar against the actual
adversary (a same-operator compromise gets all 3 anyway). One opaque store +
fingerprint verification is simpler and equally strong.

4. **Traffic analysis still wins.** Even with encrypted blobs, the server
   sees *Alice fetch-then-connect-to-Y with matching timing/size*. Encryption
   hides content, not pattern. → Needs **PIR** (scaffolded as
   `handle_pir_query`) or cover traffic. Remaining metadata leak; document it.

5. **Key-in-RAM on the server is moot** under client-side encryption — the
   server has no key to hold. (Reinforces §3.)

6. **Availability.** "Must retrieve all three" = three single points of
   failure. → Use `k`-of-`n` erasure (any 2/3 suffice).

7. **Integrity.** A hostile server can return a poisoned/missing shard →
   wrong or no address. → **Sign each shard** (ML-DSA, already in protocol);
   verify on reassembly.

8. **Chicken-and-egg on the key.** To decrypt Bob's address you need a key.
   Don't derive it from the session secret (you need the address to start the
   session). → Derive it from **Bob's public ML-KEM key**, which Alice has
   after out-of-band import. The record is "addressed to Bob's public key,"
   decryptable post-import with no prior connection.

9. **Product trade-off.** Closed contact-book kills open discovery: you cannot
   message a stranger or receive a first message from a non-contact. First
   contact requires out-of-band key exchange — which Add already does (import
   + fingerprint verify). Deliberate constraint; state it to users.

### 4.2 Recommended shape (closes the holes)

```
- Opaque blob store, content-addressed by H(shard).
- Each address record encrypted under the CONTACT's public ML-KEM key.
- k-of-n erasure coding; signed shards; no ACL; no composition server.
- Independent operators for the n servers.
- (Optional, later) PIR to hide which contact is being resolved.
```

Result: a single server compromise / seizure yields only ciphertext; the
operator cannot read IPs, Null IDs, or the contact graph.

---

## 5. Current hardening already present

- PoW (difficulty 8) on `addr_record` writes → resists DHT spam/flood.
- ML-DSA-87 signature on every record → only key holder can publish an ID.
- Nonce-log replay protection → blocks duplicate writes.
- TTL (1h) → records expire; no permanent plaintext history (operator can
  still poll, but the window is bounded).
- All crypto in-process Rust; no external GnuPG binary.

---

## 6. Known gaps (today)

- [ ] Bootstrap DHT stores IP↔ID in plaintext (see §2).
- [ ] No at-rest encryption of local client store.
- [ ] No PIR → query/contact resolution linkable by traffic analysis.
- [ ] Bootstrap servers co-located under one operator (no diversity).
- [ ] DNS SRV discovery unused (falls back to hardcoded list).
