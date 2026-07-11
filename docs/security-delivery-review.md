# Security & Privacy Review: Delivery Implementation (ACS2.6)

## 1. relay-purge Implementation Review

### Location: `/home/amu/Gnoppix/messenger/rust/relay/src/main.rs`

**What is done:**
- ✅ Recipient NID extracted from payload with `.unwrap_or("")` fallback → early rejection if empty
- ✅ Timestamp extracted and freshness checked (`check_timestamp_freshness`)
- ✅ Fingerprint extracted from payload
- ✅ Signature extracted from payload
- ✅ Null ID derivation verified: `compute_null_id(&purge_fp) == purge_recipient`
- ✅ GPG detached signature verification via `verify_gpg_detached`
- ✅ Nonce replay check via `check_and_record_nonce_str`
- ✅ BOTH in-memory and SQLite purge: `DELETE FROM mailbox_entries WHERE recipient_nid = ?`
- ✅ Audit logging via `tracing::info!`

**Actual code check (nonce key):**
```rust
let nonce_hash = format!("purge:{}:{}", purge_fp, purge_nonce);
```
- The nonce key uses `purge:` prefix which is specific to this operation. ✓ Good.

**Security analysis:**
- **Authentication**: GPG signature proves requester owns the private key for the fingerprint ✓
- **Authorization**: null_id derivation proves the fingerprint matches the mailbox being purged ✓
- **Replay protection**: Nonce check prevents replay attacks ✓
- **Timestamp protection**: Freshness check prevents old replay ✓
- **Complete purge**: Both memory and database cleared ✓

---

## 2. p2p-receipt Implementation Review

### Location: `/home/amu/Gnoppix/messenger/rust/p2p/src/protocol.rs` and `client/src/main.rs`

**Recipient side (sending receipt):**
- ✅ `P2pReceipt` struct defined with msg_hash, received_at, seq
- ✅ `build_p2p_receipt()` creates WireEnvelope with correct structure
- ✅ Signature data format: `"p2p-receipt:{msg_hash}:{received_at}:{seq}"` (line 1911)
- ✅ Sent after successful decryption (line 1923, after ack at line 1905)
- ✅ Uses recipient's own GPG key (sign_for_transport)
- ✅ **Hash is now ciphertext hash** — hashes ciphertext, not plaintext, to match sender's msg_hash

**Sender side (verifying receipt):**
- ✅ `verify_receipt_signature()` extracts msg_hash, received_at, sig (lines 1949-1960)
- ✅ Signature data format matches recipient's signing string ✓
- ✅ Uses `dht_core::verify_signature` (Sequoia in-process) ✓
- ✅ Returns false on empty signature (prevents panic) ✓
- ✅ **Uses recipient_fp as expected signer** — verifies receipt comes from intended recipient
- ✅ **Receipt hash matching** — `receipt_msg_hash == msg_hash` prevents forged receipts

**Privacy analysis:**
- **No content leak**: msg_hash is SHA-256 of ciphertext; recipient can compute without revealing content ✓
- **No sender identity leak**: Receipt only sent to the connected peer (direct P2P) ✓
- **Opt-in timing**: Recipient chooses when to reveal read time (after decrypt) ✓

---

## 3. Edge-Core Mode Implementation Review

### Location: `/home/amu/Gnoppix/messenger/rust/relay/src/main.rs`

**What is done:**
- ✅ CLI arg `--allow-relay` with `default_value = "false"` (line 866)
- ✅ `allow_relay: bool` field added to `RelayState` struct (line 524)
- ✅ `RelayState::new()` takes `allow_relay` parameter (line 446)
- ✅ Check in `relay-forward` handler BEFORE any forwarding logic (lines 1387-1399)
- ✅ NACK response sent with explanation (returns early, sender gets rejection)

**Security analysis:**
- **Default secure**: Edge mode (deny transit) by default ✓
- **Opt-in required**: Must explicitly set `--allow-relay` for core behavior ✓
- **Clear rejection**: Sender gets explicit error message ✓

---

## 4. HMAC on relay-purge (SECURITY FIX M8)

### Location: `/home/amu/Gnoppix/messenger/rust/relay/src/main.rs` lines 1601-1611

**What is done:**
- ✅ HMAC verification added when `shared_secret` is configured
- ✅ HMAC data format: `"relay-purge:{recipient_nid}:{timestamp}"`
- ✅ Client includes optional `auth_hmac` field (empty for GPG-only auth)
- ✅ Two-factor authentication: GPG signature AND HMAC when both available

**Security analysis:**
- **Defense in depth**: Optional HMAC provides additional auth factor for federation operations
- **No breaking change**: Empty HMAC accepted when no shared_secret configured

---

## 5. Summary Table (COMPLETE)

| Feature | Status | Security Level | Notes |
|---------|--------|----------------|-------|
| relay-purge sig verification | ✅ Done | High | Full GPG + null_id check |
| relay-purge nonce replay | ✅ Done | High | Specific nonce key format `purge:{fp}:{nonce}` |
| relay-purge memory+disk purge | ✅ Done | High | Both cleared atomically |
| relay-purge HMAC (optional) | ✅ Done | High | Verified when relay has shared_secret |
| p2p-receipt signing (recipient) | ✅ Done | High | Correct signature format |
| p2p-receipt verification | ✅ Done | High | Uses correct fingerprint |
| p2p-receipt hash matching | ✅ Done | High | Prevents forged receipts for other messages |
| Edge-core mode enforcement | ✅ Done | High | Default-deny, opt-in |

---

## 6. Pre-existing Lint Cleanup (completed)

**Files fixed:**
| File | Issue | Status |
|------|-------|--------|
| `protocol/src/braid.rs:122` | `manual_div_ceil` | ✅ Fixed |
| `crypto/src/kyber.rs:120` | Unused import `Nonce` | ✅ Fixed |
| `crypto/src/delivery_tokens.rs:22` | Unused import `Zeroize` | ✅ Fixed |
| `crypto/src/pir.rs:34` | Unused import `ZeroizeOnDrop` | ✅ Fixed |
| `relay/src/main.rs:15` | Unused import `PermissionsExt` | ✅ Fixed |
| `crypto-utils/src/lib.rs` | Redundant closures | ✅ Fixed |
| `crypto/src/secure_mem.rs` | Unsafe function calls in unsafe fn | ✅ Fixed |

**Why these were present:** Development artifacts from incomplete refactoring or Rust edition migrations (2015→2018→2024). They did not affect security or functionality.

**Are they important?** No - unused imports have zero runtime impact. The unsafe function warnings were cosmetic (unsafe functions already, just needed explicit unsafe blocks per Rust 2024 semantics).

---

## 7. Attack Scenarios Considered

**Scenario: Malicious relay admin tries to purge other users' mailboxes**
- **Mitigation**: GPG signature + null_id derivation check. Cannot forge without private key.
- **Status**: ✅ Protected

**Scenario: Replay relay-purge to cause message loss**
- **Mitigation**: Nonce tracking with specific prefix. First purge succeeds, subsequent rejected.
- **Status**: ✅ Protected

**Scenario: Fake p2p-receipt to show "read" status falsely**
- **Mitigation**: GPG signature required. Without recipient's private key, cannot forge.
- **Status**: ✅ Protected (signature verified against expected recipient)

**Scenario: Forged receipt for wrong message**
- **Mitigation**: Hash comparison ensures receipt matches sent message.
- **Status**: ✅ Protected

**Scenario: Mobile battery drain via federation transit**
- **Mitigation**: `--allow-relay` defaults to false. Mobile nodes must opt-in to become transit points.
- **Status**: ✅ Protected

**Scenario: Stale ciphertext accumulation on relay**
- **Mitigation**: `relay-purge` called after every successful `read`. Mailbox entries deleted.
- **Status**: ✅ Protected

---

## 8. Risk Assessment: LOW

All delivery features have strong security:
- `relay-purge`: Authenticated deletion with GPG + null_id check + optional HMAC
- `p2p-receipt`: Proper signature verification against expected recipient + hash matching
- `--allow-relay`: Default-deny with explicit opt-in

No remaining security gaps for delivery implementation.