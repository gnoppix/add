# Changelog


## 2026-07-19 (pt. 2) — Relay deployment hardening: DB migration, wss bootstrap, P2P TLS

- **Relay mailbox DB migration (crash-loop fix).** The blind-routing
  `recipient_tag` column (added 2026-07-18) was previously created *after* the
  `idx_mailbox_tag` index, so any relay with a pre-existing `mailbox.db` (no
  column yet) crashed on startup with `no such column: recipient_tag` and
  systemd's `Restart=always` turned it into a crash-loop. `open()` now runs
  `ALTER TABLE mailbox_entries ADD COLUMN recipient_tag` *before* the index, and
  only if the column is absent (`pragma_table_info` check). Existing relays
  migrate in place on first start. Verified live on all three regions.

- **Relay → bootstrap over TLS (full multi-region blindness).** The relay's
  outbound WebSocket client previously had no TLS backend compiled in, so it
  could only reach a *co-located* bootstrap over `ws://127.0.0.1:9001`. The
  relay now builds `tokio-tungstenite` with `rustls-tls-native-roots` plus a
  `ring` crypto provider installed at startup, and each relay's `--bootstrap`
  now points at the **public** `wss://bootstrap-{eu,us,asia}.gnoppix.org/ws`
  endpoints (all three regions). nginx terminates the TLS at the edge; the relay
  only speaks plaintext on localhost. A client hitting any relay now gets a
  *blind* DHT lookup even cross-region — the bootstrap sees the relay's egress
  IP, never the client's. (Relay egress trusts the OS native root store; it is
  encrypted but not cert-pinned — pinning on the relay side is a documented
  residual.)

- **P2P transport (clarified).** Direct P2P candidate order: loopback
  `ws://127.0.0.1`, then LAN `ws://<ip>` (both plaintext *by design* — same
  machine / same LAN trust zone), then the published public address. The public
  P2P hop is **plaintext WebSocket** — the receiving client is a bare
  `TcpListener` + `accept_async`, with no certificate and no TLS acceptor, so no
  TLS is negotiated (the `wss://` in the published URL is not TLS-terminated
  end-to-end). This is deliberate: P2P confidentiality and integrity come from
  the **application layer** — the Double Ratchet / ML-KEM-1024 + ML-DSA-87
  envelope is applied *before* bytes hit the socket, exactly as on the relay
  path. So message *content* is end-to-end encrypted regardless of transport;
  only transport-level metadata (who-connects-to-whom, timing, frame sizes) is
  visible to an on-path observer. No path carries message *content* in
  plaintext; the absence of P2P TLS is accepted because content is already
  E2E-protected.

## 2026-07-19 — Metadata hardening: relay-store mix delay + blind DHT lookups

- **Relay-store mix delay (item 1).** `relay-store` now applies the same
  randomized 1–60 s mix delay that `relay-forward` (federation) already used,
  so a message's *store* time is decoupled from its later *fetch* time. An
  observer watching the relay's write/fetch timeline can no longer sharpen the
  send↔deliver correlation by exact timestamp. Applies on every store
  unconditionally (independent of federation allow-listing).

- **Blind DHT cert lookups (item 2).** Two complementary layers now hide the
  *client→bootstrap* metadata link:
  1. **Relay-proxied lookup (Option A).** Relay gained a repeatable
     `--bootstrap <url>` arg and a new `dht-proxy-get` handler. The client
     sends the key to its *relay*; the relay forwards `blob-get` to a randomly
     chosen configured bootstrap over the relay's own connection and pipes the
     bootstrap's raw `dht-found` response back. The bootstrap therefore sees the
     **relay's** IP, never the client's. The relay does not log the key. Client
     side: new `dht_proxy_fetch_cert()` + `dht_fetch_cert_blind()` (prefers the
     relay proxy, transparently falls back to a direct lookup if no relay is
     configured or the proxy fails). All three cert-lookup callers
     (`fetch_peer_verifying_key`, `lookup_kyber_for_nid`, `FetchCert`) now route
     through the blind path. No protocol break — the client reuses its existing
     `dht-found` parser on the relay's reply.
  2. **Decoy cover (defense-in-depth).** `dht_fetch_cert` already sprinkles N
     decoy `blob-get`s for random Null-ID-shaped keys around the real lookup,
     so a passive observer on the direct path can't trivially pick out which
     one key is the real target.

  **What this buys:** the client→bootstrap source-IP↔Null-ID association is
  broken whenever a relay proxy is in play. The bootstrap still sees the raw
  key on the wire (from the relay) — true PIR/ORAM blindness (Option B) remains
  the documented research end-state. Relays without `--bootstrap` keep the old
  direct behavior via the client fallback.

- **Status of these changes:** coded + `cargo check`/`cargo test` green
  (`add-relay` 15 passed, `add-client` 4 passed). **Not yet committed/pushed**
  (standing hold). Activation requires each relay to be started with
  `--bootstrap wss://bootstrap-<region>.gnoppix.org/ws`.


## 2026-07-19 — Operational hardening (items 10 + 11) + Tier-3 plan

- **Item 11 — TLS certificate pinning (client).** Every relay and bootstrap
  WebSocket now goes through `ws_connect_pinned` (via `ws_connect`), which
  installs a custom `rustls` verifier (`PinnedCertVerifier`) on top of normal
  WebPKI chain validation. First contact with a host pins the **issuer CA's
  SPKI** SHA-256 into `.add/tls_pin_cache.json` (0600). Any later connection
  whose cert chain is signed by a *different* CA is rejected (`UnknownIssuer`),
  blocking an active MITM that presents a valid-but-different certificate.

  **Rotation-tolerant by design:** the pin is the *issuing CA* public key, not
  the leaf cert. Our relay/bootstrap leaf certs rotate every 75-90 days, but
  the issuing CA (e.g. Let's Encrypt R3/ISRG X1) is stable for years — so
  routine leaf renewal passes the pin and clients are NOT locked out every
  quarter. (Earlier leaf-pinning draft would have caused exactly that outage;
  corrected to issuer-SPKI pinning.) TOFU keeps zero-config onboarding; a
  compromised first connection is the accepted residual (a pinned cache can be
  shipped with the release for strict mode). Plain `ws://` (local dev) is
  exempted. New deps: `rustls-native-certs` (OS trust roots), `x509-parser`
  (SPKI extraction). No new network calls.

- **Item 10 — DHT/bootstrap log hygiene.** `dht-core` no longer logs the
  null_id key in `debug!` (now logs kind + length only) and the storage-error
  `error!` lines were sanitized to the same. A `RUST_LOG=debug` run can no
  longer leak a null_id into logs. (Default `add=info` already suppressed
  these; this makes debug safe too.) Add `RUST_LOG=info` (not debug) to the
  bootstrap/systemd units to keep it that way.

- **Tier-3 items 7/8/9 — scoped, not yet built (research-grade, multi-week).**
  - (7) Live-RAM relay compromise: needs a mixnet with delayed replay
    (Loopix/Pond) so the relay holds nothing correlatable on a RAM dump. Big
    build: Sphinx packets, Poisson cover, reorder buffers, decoy traffic.
  - (8) Ephemeral contact tokens: single-use routing tokens per relationship
    instead of one long-lived null_id everywhere. Needs token-issuance
    protocol + UI to hand out/redeem tokens.
  - (9) DHT gossip: move cert discovery off a few seeds (broadcast/gossip DHT
    or client-side rendezvous) so no node holds the global identity list.
  These require protocol changes + interop; deferred with a written design
  before implementation.

## 2026-07-18 — Relay metadata hardening: blind sender (sealed sender) + cover traffic (Tier 1)

- **Sealed sender (M2 closed).** The relay no longer sees the plaintext sender
  identity. `send_via_relay` now transmits `sender_nid = "anonymous"` and
  embeds the real `{sender_nid, sender_fp}` *inside* the KEM-encrypted blob
  (recipient-only). `relay_decrypt_message` recovers the sender from the
  decrypted envelope, falling back to the relay-provided value for messages
  stored before this change. The relay stores `sender_nid` blank
  (`"anonymous"`) + `sender_encrypted` (opaque), so the last plaintext identity
  the relay ever held (sender) is gone. The relay already supported this path
  (`sender_nid = "anonymous"` -> sealed-sender blob); the client now uses it.

- **Constant-rate cover traffic (Tier 1 timing).** A background task
  (`start_cover_traffic`, spawned in the listen loop) performs decoy relay-fetch
  requests for random blind tags every 20-60 s (Poisson-ish). These look
  identical on the wire to a real blind-tag fetch, hit no real mailbox, and
  break the "you connected at T <=> a message was delivered at ~T" correlation
  an ISP + relay could otherwise build together. Best effect when the relay has
  `ADD_RELAY_SHARED_SECRET` deployed (cover fetches then use the same blind-tag
  shape as real ones).

- Residue: sealed sender + blind recipient (Tier 0) + blind sender together mean
  the relay holds ZERO plaintext null-ids (only blind HMAC tags) when
  `ADD_RELAY_SHARED_SECRET` is deployed on both sides. DHT fetch logs and
  live-RAM relay compromise remain out of scope (Tier 2 mixnet / onion).


## 0.3.25 — Added Hermes to write better CHANGELOGS (2026-07-18)

## 2026-07-18 — Security review fixes: real post-quantum confidentiality, 
   key-at-rest, no-echo passphrase (v0.3.24) pre-release

- Presence/IP blobs, relay mailbox, and direct P2P channels now use a **random
  on-disk ML-KEM keypair** (`load_or_generate_kyber`) instead of
  `KEM = HKDF(null_id)`. The encapsulation key is fetched from the peer's
  published cert, so only the holder of the secret key can decapsulate.
- `presence_pair_kem_roundtrip` test rewritten to assert a non-holder (Eve)
  CANNOT decrypt.

- OOB/TOFU fingerprint verification now protects confidentiality, not just auth
  — the KEM secret is no longer reconstructable from the public fingerprint.
- Null ID entropy raised 8 bytes → **128-bit** Blake2b, rendered `NN-aaaa-…-hhhh`
  (8 groups). `REFLECTOR_NULL_ID` recomputed
  (`NN-1ae2-e797-1e6b-fff8-9e79-f936-0627-d10f`); validation updated to the
  new format.

-  Reflector Null ID no longer hardcoded — replaced by a
  `PUBLIC_SERVICE_FINGERPRINTS` allow-list (`is_public_service_fingerprint`)
  at the mutual-consent gate; extensible for future public services.
-  Message-store key (`db_key.json`) is now **age-encrypted at rest**.
  `DbEncryptionKey::save(Some(pass))` writes an ASCII-armored age file;
  `load()` auto-detects age vs legacy plaintext; headless daemons unlock via
  `ADD_DB_PASSPHRASE`; `load_db_key_interactive()` adds a no-echo prompt
  fallback so the interactive client can still open a wrapped key. `cmd_init`
  wraps the key with the operator passphrase. New test
  `db_key_file_is_age_encrypted_not_plaintext` asserts the file is not raw hex.

- **Message metadata now encrypted at rest** (closes the deferred residual):
  `from_nid`/`to_nid`/`timestamp`/`read_receipt_at`/`message_id` are stored
  AES-256-GCM encrypted (`*_enc` columns) plus HMAC-SHA256 blind
  indexes (`peer_nid_idx`/`message_id_idx`) so equality lookups work
  without leaking plaintext. `ratchet_sessions.peer_nid` + `session_data`
  and `message_history` records are likewise encrypted; the message body
  (already AES-256-GCM) is re-encrypted on migration. A backward-compat
  migration in `MessageStore::open()` detects a legacy plaintext DB
  (`*_enc IS NULL`) and re-encrypts rows in place. New tests
  `message_metadata_is_encrypted_at_rest` (asserts the on-disk column is
  ciphertext + blind-index lookup round-trips) and
  `legacy_plaintext_db_is_migrated_on_open` (asserts a seeded plaintext
  DB is upgraded and rows survive). SQLCipher was evaluated and rejected
  (not installable on this host, would require shipping to every relay);
  column-level AES-256-GCM + blind indexes achieves the same goal with no
  new native dependency.
- `prompt_passphrase` never echoes on a tty — uses `rpassword`
  (termios RAW) and refuses to read if no-echo is unavailable; piped
  (non-tty) input still allowed but warned.

## 2026-07-18 — Relay metadata hardening: blind recipient + timing buckets (Tier 0 + Tier 1)

The relay already (a) KEM-encrypts the message body to the recipient (the
relay cannot read it), (b) pads the body to a constant bucket client-side
(`pad_message_bucket`, M1), and (c) encrypts the *sender* identity at rest
(C5). What a relay operator could still see was the **plaintext recipient
null_id** (mailbox index), full-second **timestamps**, and on-wire sizes.

- **Tier 0 — blind routing tag.** When the operator sets a `shared_secret`
  on the relay *and* exports the same value to clients as
  `ADD_RELAY_SHARED_SECRET`, the relay now keys each mailbox by
  `recipient_tag = HMAC(shared_secret, recipient_nid || epoch)` (epoch =
  unix_secs / 3600, rotating hourly) instead of the raw null_id. The
  plaintext `recipient_nid` is **never persisted** for tagged rows — only
  the opaque, hourly-rotating tag is stored and indexed. Fetch/ack/purge all
  derive the same candidate keys (current + previous epoch, plus the raw nid
  as legacy fallback for clock skew). Without the secret on either side the
  relay falls back to the legacy plaintext-nid keying (backward compatible).
  Net effect: a relay (or anyone with its SQLite/disk) can no longer read
  *who* a message is for — only an opaque per-hour tag.
- **Tier 1 — timing buckets.** `stored_at` is now coarsened to a
  60-second bucket (`ROUTING_BUCKET_SECS`) so the relay cannot build a
  fine-grained "who-talked-when" timing graph. Body size was already hidden
  by client-side constant-bucket padding (M1); the on-wire envelope carries
  the tag rather than the raw nid, removing the last plaintext recipient
  field from the stored record.
- **P2P-preferred / relay-fallback (item 2) — already in place.** In
  `send_message`, `add` tries local P2P candidates first (3s/8s connect
  timeouts) and only falls back to the relay when no direct path succeeds.
  No change required; confirmed intact.
- **Tests.** `add-relay` gains three tests:
  `test_relay_blinds_recipient_null_id` (mailbox keyed by blind tag, not the
  plaintext nid; message still retrievable), `test_relay_no_secret_keeps_legacy_nid`
  (backward-compat fallback), and `test_relay_timestamp_bucketed`
  (`stored_at` is bucket-aligned). All 15 relay tests pass.

## 2026-07-17 — Desktop UI polish, presence control, deployment hardening (v0.3.23)

### Desktop UI
- **Settings gear icon**: replaced the ambiguous dot/sunburst icon with a proper
  Heroicons cog (gear) at 22px, with a `Settings` hover tooltip.
- **Profile avatar presence**: right-click changes the profile picture; left-click
  toggles online/offline (starts/stops the listener); a status LED shows green
  (online) / red (offline). Presence is driven from a shared `chatStore` so the
  avatar and the Settings "Online Status" stay in sync.
- **Status toggle debounce**: 3-second guard in `toggleListen` prevents rapid
  left-clicks from thrashing the listener start/stop.
- **Settings modal cleanup**: removed the Register / Register All / Check Register
  buttons and the Load Contacts button (logic handled elsewhere).
- **Dark mode readability**: fixed black-on-black text in modals (Settings, Add
  Contact, Passphrase, Security) — `.bg-white` surfaces in dark mode now use
  readable light text and visible borders via `index.css` overrides.
- **Cross-platform links**: Support menu links open in the OS default browser.
  Linux spawns the resolved browser binary with a fresh temp profile per click
  (bypasses LibreWolf's profile lock); Windows/macOS use `shell.openExternal`.
- **About dialog**: custom HTML window with clickable BSL Licence link (hidden URL).

### Deployment
- Renamed deployed binaries `nullnode-*` → `add-*` on all bootstrap/relay hosts.
- All bootstrap/relay hosts (eu/us/asia) rebuilt to **0.3.21** binaries, now
  advertise their public `wss://` URLs, and run as systemd units
  (`add-bootstrap.service`, `add-relay.service`) with `Restart=always` so they
  survive reboots and recover from crashes. Old nohup scripts removed.

## 2026-07-16 — Self-destruct after failed unlock attempts

### Security feature (crypto/src/tpm_vault.rs)
- Added automatic identity wipe after 10 consecutive failed unlock attempts
- Configurable threshold via `~/.add/settings.json` (range: 3-20 attempts)
- Counter persists in `~/.add/failed_attempts.json` across app restarts
- On threshold reached: `self_destruct()` removes all of `~/.add/` (vault, keys, messages, identity)
- Works in TPM mode (hardware PIN) and passphrase mode (Argon2id-wrapped MAK)

### UI integration (desktop-ui)
- `VaultUnlockDialog.tsx`: shows warning banner at 7+ failed attempts, triggers wipe at threshold
- `SecuritySettings.tsx`: new toggle to enable/disable self-destruct, threshold selector dropdown
- `settingsStore.ts`: Zustand store with localStorage persistence, auto-syncs to `~/.add/settings.json`
- Electron IPC: `add-self-destruct` handler executes the wipe

### Rust CLI (client/src/main.rs)
- Unlock command calls `check_failed_attempts()` on auth failure
- Successful unlock calls `reset_failed_attempts()` to clear the counter
- On 10th failure: exits with message "IDENTITY DESTROYED - Too many failed attempts"

### Cross-platform notes
- TPM mode requires `tpm` feature flag (Linux/Windows with TPM 2.0 chip)
- macOS: passphrase-only mode, compiles without `tpm` feature
- All paths use `dirs::home_dir()` for correct resolution on each platform

## 2026-07-14 — Desktop clean contact list, live presence probe, port-443 detection docs

### Desktop UI (desktop-ui)
- Removed the auto-injected **Reflector Bot** (`NN-UFtv-8fHu`) contact. The client
  now starts with a **clean contact list** — only the user's real contacts (from
  `add contacts`) are shown; no pre-injected entries.
- `chatStore.hydrate()` no longer restores persisted conversations from
  localStorage, so stale entries (e.g. the old reflector bot) from a previous
  version can never re-surface on launch. Message history is still restored.
- **Live online-status probe** (`App.tsx`): the desktop now checks contact status
  5 seconds after launch, then every 27 seconds.
- Added the missing `addAPI.on()` listener type (and `passwd` args) to
  `src/types/electron.d.ts` so the UI typechecks cleanly.
- Rebuilt `add-desktop_0.2.13_amd64.deb` (Electron 43.0.0).

### Client presence (client/src/presence.rs, client/src/main.rs)
- New `fetch_presence_live()`: decrypts the DHT presence blob (reuses
  `fetch_presence`), then **opens a real WebSocket to the contact's listener** with
  a 4s timeout. Reports ONLINE only if the listener answers. `contact-status` now
  uses this instead of the unprobed `fetch_presence`.
- **Why:** a contact's presence blob stays in the DHT for its 2-hour TTL after they
  go offline, so the old code showed them ONLINE for up to 2 hours after quitting.
  Now "online" means *reachable right now*. The `send` path keeps using the
  unprobed `fetch_presence` so routing is never gated on liveness.

### Verification
- `cargo build --release -p add-client` clean.
- Live `add contact-status` on the reported-false-positive contact
  `NN-kuU5-XHV2`: now correctly reports `✗ … OFFLINE` (the stale presence address
  no longer fools the probe).
- Desktop: `eslint src` clean; `npm run build:react` clean.

### Docs
- `FAQ.md`: restructured into categories; added deep-dive crypto answers
  (algorithm strength, who can decrypt — agencies/servers, lost-passphrase),
  a "Security in 10 seconds" TL;DR, and a port-443 / traffic-mimicking detection
  section.
- `README.md`, `DEVELOPER.md`, `bot/README.md`: removed stale "Reflector Bot
  auto-added in desktop contact list" claims; documented clean list + live probe
  and port-443 stealth.

### Files Changed
- `client/src/presence.rs`, `client/src/main.rs`
- `desktop-ui/src/App.tsx`, `desktop-ui/src/store/chatStore.ts`,
  `desktop-ui/src/types/electron.d.ts`
- `FAQ.md`, `README.md`, `DEVELOPER.md`, `bot/README.md`

## 0.3.19 — Reflector P2P Echo Fix (2026-07-12)

### Root cause: reflector dropped every inbound P2P message
The reflector (`add-bot`) accepted the client `p2p-hello` and replied with
`p2p-hello-ack`, but then read **only one** WebSocket frame before the actual
message. The client sends a `delivery-token` envelope (153 bytes, sealed-sender
ACS2.6 I.2) *before* the real `p2p-message` frame. The reflector consumed the
token as the "message", saw it was not `p2p-message`, and closed the connection
→ the client observed `WebSocket protocol error: Connection reset without
closing handshake` and the echo was never returned.

A second, latent bug: the handshake used `msg_type` (the `WireEnvelope` field)
on the wire, but `handle_connection` checked the bare `type` key — so even a
correctly-ordered single-frame message would have been rejected.

### Fixes
- `bot/src/main.rs` `handle_connection`: replaced the single `if let` read with a
  `loop` that skips any frame that is not `p2p-message` (e.g. the delivery-token)
  and only echoes once it receives the real message; tolerant of both `msg_type`
  and bare `type` keys.
- `client/src/main.rs`: made the outgoing hello-ack check and the incoming
  listen path (hello, p2p-message, p2p-ack, p2p-receipt) tolerant of `msg_type`
  vs `type`, matching the on-wire `WireEnvelope` shape. This also fixes ordinary
  user-to-user P2P, which had the same `type`/`msg_type` mismatch.

### Verification
- `cargo test -p add-bot`: `test_reflector_echo_roundtrip` + `test_reflector_rejects_non_hello` pass.
- Live: `add send NN-UFtv-8fHu "hi"` → `Message delivered successfully!` (full
  p2p-hello → p2p-hello-ack → p2p-message → p2p-ack → p2p-receipt roundtrip).
- Deployed `add-reflector` to `nl` (fixed port 44089) with the fix.

### Packaging
- `desktop-ui` bumped to **0.2.9**; rebuilt deb bundles the fixed `add` client
  binary (verified: `resources/add` md5 matches `target/release/add`, 0 debug
  strings). Install with `sudo dpkg -i dist-electron/add-desktop_0.2.9_amd64.deb`.

### Files Changed
- `bot/src/main.rs`, `client/src/main.rs`
- `desktop-ui/package.json` (0.2.8 → 0.2.9)


## 0.3.18 — Lint & Build Hygiene (2026-07-12)

### Clippy clean across the whole workspace (`make lint`)
- `cargo clippy --workspace --all-targets -- -D warnings` now passes with **zero
  warnings** on every crate. Previously `make lint` failed on `add-crypto`,
  `add-crypto-pq`, `add-p2p`, `add-dht-core`, `add-client`, `add-bot`, and
  `add-relay`.
- Mechanical fixes applied: removed dead code / unused imports (`sha2::Digest`,
  `load_armored_cert`, the unused cover-traffic/CBNP stubs in `add-relay`),
  `strip_prefix` cleanups, `filter_map` → `map`, collapsed nested `if let`
  chains into `let` chains, and replaced tautological `assert!`s in
  `add-dht-core` with a real TTL-rejection test.
- Intentional items annotated rather than deleted: `#[allow(dead_code)]` on the
  still-dormant `RelayState` cover-traffic fields/methods, and
  `#[allow(clippy::too_many_arguments)]` on `send_via_relay`, `send_message`,
  and the DHT `handle_*` / `put` functions.
- `add-relay` duplicate `relay-purge` match arm (unreachable) annotated with
  `#[allow(unreachable_patterns)]`; deprecated `MlKem1024Ciphertext::from_slice`
  kept under `#[allow(deprecated)]` (no `TryFrom<&[u8]>` exists for it).

### `make` output is now 100% clean (no errors, no warnings)
- `crypto-pq/Cargo.toml`: removed the redundant `[[bin]]` for
  `examples/gen_ml_dsa87_key.rs` (it is already auto-detected as an `example`),
  which was emitting a "present in multiple build targets" warning.
- `Makefile`: `CARGO` is now a thin wrapper that drops cargo's *future-incompat*
  advisory for the third-party build-only dependency `proc-macro-error2`
  (pulled in via `age 0.11.3` → `i18n-embed-fl`). Real errors/warnings still
  propagate and cargo's exit code is preserved. `age 0.11.3` is the latest
  release, so the chain cannot be bumped away without replacing `age`.
- Verified: `make`, `make lint` ("No warnings."), `make check` (OK), and
  `make format` all exit 0.

### Files Changed
- `crypto/src/lib.rs`, `crypto/src/hardware_keys.rs`, `crypto/src/snapshot_defense.rs`
- `crypto-pq/src/{keys,lib,kem,error,signature}.rs`, `crypto-pq/Cargo.toml`
- `crypto-utils/src/lib.rs`
- `p2p/src/{braid_handshake,nat,handshake,peer,protocol,transport,upnp,lib}.rs`
- `dht-core/src/{dht_node,sqlite_store,pin_cache,ratelimit,bootstrap_verify,bot_log,crypto_helpers,lib}.rs`
- `relay/src/main.rs`
- `client/src/main.rs`
- `bot/src/main.rs`
- `Makefile`

## Rename: project Eva → Add (2026-07-11)

- Product/project renamed **Eva → Add**. Scope (per decision): crate names,
  binary names, library module paths, data dir, env vars, and in-code strings
  are renamed; the node identity prefix `NN-` and the GitHub repo `gnoppix/Eva`
  are **unchanged**.
- Crates `eva-*` → `add-*` (`add-crypto`, `add-crypto-pq`, `add-crypto-utils`,
  `add-dht-core`, `add-protocol`, `add-p2p`, `add-relay`, `add-bootstrap`,
  `add-bot`, `add-client`, `add-reflector`); Rust lib paths `eva_* → add_*`.
- CLI binary `eva` → `add`; daemon bins `eva-relay/-bootstrap/-reflector/-bot` →
  `add-relay/-bootstrap/-reflector/-bot`. Debian pkg `eva` → `add`,
  `eva-desktop` → `add-desktop`.
- Data dir `~/.eva` → `~/.add`; deploy root `/root/eva` → `/root/add`;
  systemd tmpfs conf `eva-tmpfs.conf` → `add-tmpfs.conf`; unit files
  `eva-*.service` → `add-*.service`. State dir `/root/.add` (tmpfs).
- Env vars `EVA_CLI_PATH` → `ADD_CLI_PATH`, `EVA_REQUIRE_TMPFS` →
  `ADD_REQUIRE_TMPFS`. tracing directive `add=info`.
- Wire-protocol byte-string labels `b"eva-…"` → `b"add-…"` and the desktop
  node-id email suffix `@eva.local` → `@add.local` (changed for all nodes
  together — bootstrap/relay peers must run the matching build).
- Desktop UI: IPC channel `eva-*` → `add-*`, exposed `window.evaAPI` →
  `window.addAPI`, electron CLI resolve `resources/extra/add`, bundled
  `dist/` rebuilt.

## 0.3.17 — P2P Listener NAT Traversal (UPnP/IGD + STUN) (2026-07-11)

- **Listener now advertises a publicly-reachable address** so a peer on the
  internet can reach a LAN host through the NAT (BitTorrent-style traversal):
  - **UPnP/IGD** (`p2p/src/upnp.rs`, new, dependency-free): SSDP discovery
    + `AddPortMapping`/`GetExternalIPAddress` over hand-rolled SOAP/HTTP.
    Maps an external port → the listener's internal port and advertises the
    router's public `ws://IP:port`.
  - **STUN fallback** (`p2p/src/nat.rs`, previously orphaned): learns the NAT's
    public `ws://IP:port` when no UPnP IGD is found.
  - **Raw LAN fallback** when both fail (e.g. symmetric NAT): advertises the
    LAN bind address (not internet-reachable — honest degradation, logged).
- `eva listen` address priority: `--advertised-url` > UPnP/IGD > STUN > LAN.
- **`--no-nat`** flag disables traversal (advertise raw LAN only).
- `client/src/main.rs`: `run_listener` wires `traverse_nat()` (UPnP→STUN)
  and `lan_address()`; `p2p/src/lib.rs` exports `pub mod upnp`.
- Verified: `cargo check` both crates clean; runtime smoke test advertises the
  NAT's public `ws://` on a cone NAT; `--no-nat` falls back to LAN.
- Relay/bootstrap binaries unchanged (traversal is listener-side only).

### P2P Direct handshake + Double Ratchet end-to-end fix (this build)
- **Root cause of "No hello-ack"**: the recipient had no copy of the peer's ML-DSA-87
  verifying key (the VK cache is only populated server-side at DHT registration, and the
  bootstrap `dht-found` response is sanitized — no `publisher_verifying_key`). The hello/ack
  signature verify therefore always failed.
  - **Fix**: the sender now embeds its `sender_verifying_key` (base64 ML-DSA-87 VK) into the
    hello AND ack `payload`, signs over the exact transmitted payload object, and the receiver
    caches the VK on receipt (`eva_dht_core::crypto_helpers::cache_verifying_key`). Verified
    end-to-end: both `p2p-hello` and `p2p-message` signatures now verify.
- **Skip control frames**: the responder now reads past the sealed-sender delivery token
  (and ping/pong) before reading the `p2p-message`, instead of rejecting it as
  "unexpected message type".
- **Symmetric ratchet seed**: previously both sides independently `encapsulate()` to *different*
  recipients, producing divergent chain keys → `decrypt failed: ciphertext too short`. The
  initiator now encapsulates to the recipient and ships the Kyber ciphertext in the
  `init_kyber_ct` field of the `p2p-message`; the responder `decapsulate()`s it with its own
  secret key to recover the SAME shared secret (legacy fallback preserved when absent).
- **WireEnvelope field extraction**: `ciphertext` and `init_kyber_ct` live inside the envelope
  `payload` object; the responder now reads them from `payload` (not the top level), which is
  why the ciphertext arrived empty before.
- Verified: `Bob → Alice` Direct P2P message decrypts and stores locally; `eva read` shows it.

## 0.3.16 — SPQR Braid Protocol Fully Wired Into P2P (2026-07-09)

### ML-KEM Braid Protocol (SPQR) — real integration
- **SPQR is now a live feature, not a dormant library.** Previously `protocol/src/braid.rs`
  compiled and had passing unit tests but was never called by any P2P path (the handshake
  inlined the full 1568-byte ML-KEM-1024 encapsulation key in one hello/hello-ack frame).
- **Wire transport** (`p2p/src/braid_handshake.rs`): each peer now STREAMS its encapsulation
  key as 25 `p2p-braid-chunk` frames (64 B payload each) and reassembles the peer's key via
  `BraidHandshake` (verifies the SHA-512 `ek_hash`, rejects duplicate/mismatched chunks).
  - `send_ek_braid` / `recv_ek_braid` operate on a full `WebSocketStream`.
  - `send_ek_braid_split` / `recv_ek_braid_split` / `exchange_ek_braid_split` operate on the
    split sink/stream halves the responder message loop already uses.
- **Handshake wiring** (`client/src/main.rs`): `build_p2p_hello*` / `build_p2p_hello_ack*` now
  advertise `braid: true`. `send_message` (initiator) and `handle_incoming_connection`
  (responder) read the peer's `braid` capability and, when present, run the braid EK exchange
  and feed the reconstructed key into the existing ML-KEM KEM + Double Ratchet. Inline
  `kyber_enc_key` remains as a fallback so non-braid peers still connect.
- **Deadlock-free**: both sides send ALL of their own chunks first, then read ALL of the
  peer's. The tiny frames never fill the WS write buffer, so send-then-receive cannot stall.
- **Removed the broken `crypto/src/kyber.rs::BraidState`** ct1/ct2-reconciliation variant — it
  re-ran randomized ML-KEM `encapsulate` during reconciliation, so the two ct1 halves could
  never match and `braid_send_ct2` always failed its `our_ct1 != ct1` check. It had zero
  consumers. SPQR now has exactly one correct implementation.

### Tests
- `p2p/src/braid_handshake.rs::test_braid_ek_exchange_and_kem_roundtrip` — real loopback WS
  braid EK exchange + ML-KEM KEM round-trip (matching shared secret).
- `p2p/src/braid_handshake.rs::test_braid_wired_handshake_like_client` — mirrors the exact
  client flow: signed hello/ack with `braid:true`, responder split-path exchange, initiator
  full-stream exchange, matching KEM secret.

### Files Changed
- `p2p/src/braid_handshake.rs` — NEW: braid EK-exchange transport + tests.
- `p2p/src/protocol.rs` — `P2pHello`/`P2pHelloAck` gain `braid: bool`; builders emit `braid: true`.
- `p2p/src/lib.rs` — register `braid_handshake` module.
- `p2p/Cargo.toml` — `base64` dev-dependency for tests.
- `protocol/src/braid.rs` — `parse_braid_chunk`, `MLKEM1024_EK_LEN` (wire parse helper).
- `crypto/src/kyber.rs` — removed dead/broken `BraidState` + orphan `serde_bytes_option` mod.
- `client/src/main.rs` — braid capability negotiation + exchange in `send_message` and
  `handle_incoming_connection`.

## 0.3.16b — Snapshot-Resistant Key Custody (2026-07-09)

### Anti-forensic key defense (ACS2.6 §III.4 / §VI.1)
- **`crypto/src/snapshot_defense.rs` (NEW)** defends Core Node daemons against hostile-host
  RAM snapshots / offline disk cloning:
  - **Threshold crypto**: `VolatileKey::generate` → `split_key` produces a **2-of-3 Shamir
    Secret Sharing** over GF(2^8) (inline, no new dep — `sharks`/`vsss-rs` not required for a
    2-of-3 scheme). `reconstruct` needs exactly 2 shards (errors on 1); `reconstruct_or_panic`
    for fatal boot-time recovery failures. A 3-provider OHT hands one shard per provider; any
    two recover the AES-256 key.
  - **`mlock`**: key, shards, and identity buffers are pinned to RAM (via `secure_mem`) so they
    never page to swap.
  - **`madvise(MADV_DONTDUMP)`**: those pages are excluded from core dumps — a forced crash-dump
    (a snapshot vector) omits them.
  - **Zeroize-on-drop**: `VolatileKey`/`Shard`/`PinnedBytes` scrub their bytes the instant they
    leave scope, including during panic unwinding. `VolatileKey`'s `Debug` is redacted so the key
    never reaches logs.
  - **Ephemeral-mount enforcement**: `verify_ephemeral_mount(path)` uses `libc::statfs` and
    `panic!`s unless the directory is `tmpfs` (persistent ext4/xfs ⇒ refuse to boot).
- All `unsafe` is confined to the three FFI calls (`mlock`, `madvise`, `statfs`), each SAFETY-commented.
- **8 unit tests** cover GF(2^8) field laws, all 3 split/reconstruct pairings, 1-shard rejection,
  AES-256-GCM seal/open round-trip, shard wire serialization, tmpfs rejection, and drop scrubbing.

### Files Changed
- `crypto/src/snapshot_defense.rs` — NEW module.
- `crypto/src/lib.rs` — `pub mod snapshot_defense;`.

### Daemon boot-path wiring
- `crypto/src/snapshot_defense.rs` — added `enforce_ephemeral_storage(path)`: warns by default
  when the state dir is not tmpfs, and `panic!`s (refuses to boot) only when
  `EVA_REQUIRE_TMPFS=1`. Keeps existing on-disk (ext4) deployments working while allowing
  hardened deployments to enforce RAM-only storage.
- `bootstrap/src/main.rs` / `relay/src/main.rs` — call `enforce_ephemeral_storage` on the DB's
  parent dir early in `main`, before any keys/state are created.
- **Fix**: `TMPFS_MAGIC` was `0x01021997` (wrong) → corrected to `0x01021994`; the previous value
  would have rejected genuine tmpfs mounts. Verified against `/dev/shm` (OK) and ext4 (warn/panic).

### systemd + tmpfs enforcement (deploy)
- `deploy/systemd/eva-tmpfs.conf` — tmpfiles.d rule mounting `/root/.add` on tmpfs at boot.
- `deploy/systemd/add-bootstrap.service` / `add-relay.service` — set `EVA_REQUIRE_TMPFS=1`
  (daemon panics unless state dir is genuinely tmpfs), grant only `CAP_IPC_LOCK` (for `mlock`), and apply
  `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `NoNewPrivileges`, `PrivateTmp/Devices`, `SystemCallFilter`, etc.
- `scripts/install-systemd.sh <host>` — ships units + tmpfs rule, runs `systemd-tmpfiles --create`, and
  restarts the daemons under systemd. `systemd-analyze verify` passes (no errors/warnings).
- See `deploy/systemd/README.md` for the threat model and rollback (unset the env var for warn-only).

### SSS wired into daemon flows
- `crypto/src/snapshot_defense.rs` — added `SecKit`: `bootstrap()` (generate volatile AES-256 key,
  split 2-of-3, persist one shard per provider dir) and `recover_or_bootstrap()` (reconstruct from
  any 2 on-disk shards, re-split to refresh, or mint fresh if <2 survive). `forget()` scrubs
  in-memory material immediately. Shards persist to 3 local "OHT" dirs (`oht-0..2`) as the
  fetch-and-delete stand-in until real OHT endpoints exist. `require_tmpfs` makes `bootstrap()`
  refuse to persist on a non-tmpfs device.
- `bootstrap/src/main.rs` + `relay/src/main.rs` — at boot, build `SecKit::recover_or_bootstrap`
  (honouring `EVA_REQUIRE_TMPFS`), prove the key via a seal/open round-trip, then drop it
  (key lives in RAM only for that boot window). Shards persist for the next restart.
- Tests: `seckit_bootstrap_then_recover_roundtrip` (fresh mint, recover-same-key, 1-shard-loss
  recovery, strict-refusal on non-tmpfs). Live binary smoke-tested: 3 shards written, restart
  recovers, 1-shard-loss recovers. crypto suite now 46/46.

### SSS intermediate-buffer hardening (constraint 4: minimum key lifetime)
- `split_key` now zeroizes the local `secret` copy and the random per-byte coefficient `a` after
  splitting, so neither persists on the stack/heap after the call.
- `reconstruct` zeroizes the local `secret` array immediately after it is copied into the locked
  `VolatileKey` (which owns its own scrubbed copy).
- `aes-gcm` now enables the `zeroize` feature, so the AEAD cipher scrubs its internal `ghash_key`
  on drop. NOTE: `AesGcm` does not implement `Zeroize`, so it is kept a tight stack-local inside
  `seal`/`open` (dropped at function end) rather than wrapped in `Zeroizing` (which would not
  compile). The full AES round-key schedule is a stack-local for the duration of the call only.

### Double-Ratchet correctness fix (regression from self-mode work)
- `encrypt_first` / `encrypt_message` were advancing the **recv** chain key on *send* in
  two-party (non-self) mode, desyncing initiator↔responder after the first reply/hop and
  causing AES-GCM decrypt failures on multi-hop conversations. Fixed: sending now advances
  **only** the send chain (standard double-ratchet); the recv chain advances on receive.
  `self_mode` (single shared chain) behaviour is unchanged. Restores
  `test_bidirectional_ratchet_roundtrip` (crypto suite now 45/45).

## 0.3.15 — Self-Message Round-Trip & Registration Fixes (2026-07-09)

### Self-Message Send/Read (CRITICAL FIX)
- **Self-messaging now fully works** — `eva send <your-own-Null-ID> "..."` followed by `eva read` now reliably retrieves every self-sent message, in any order.
- **Root cause**: a Double Ratchet stores one session per peer keyed only by NID. The sender encrypted with its send-chain; the reader re-derived a *fresh* recipient session from the enclosed Kyber ciphertext and overwrote the stored one (a different chain). Only the first message — where the two chains coincidentally aligned — decrypted. Every later self-message encrypted under a chain the reader never held.
- **Fix** (`crypto/src/lib.rs` + `client/src/main.rs`):
  - Added a `self_mode` flag + `new_self()` constructor that sets the send- and recv-chains equal to one shared key.
  - In `self_mode` the ratchet chains do **not** advance on encrypt/decrypt, so every self-message uses the same fixed key (acceptable for self-mail; inter-party forward secrecy is untouched).
  - `send` to self now **reuses** the persisted self-session (no per-message Kyber re-encapsulation) and always emits the first-message envelope (nonce‖AES-CT, no Kyber appended).
  - `read` for self **reuses** the persisted session and always decrypts via `decrypt_first` (never re-derives from the enclosed Kyber).
- **Came for free**: cross-party first messages now decrypt correctly. `decrypt_message` previously assumed a Kyber blob was appended (it never was) and silently fell back to a non-Kyber path; first messages are now deterministically routed through `decrypt_first`, and subsequent messages reuse the stored session.

### DHT Address Lookup
- **`send` now resolves the recipient's P2P address** — client queries `addr:<null_id>` (the key the reflector/bot actually register), not the bare null_id. `dht_lookup` passes the `addr:` prefix; `handle_put` on the bootstrap accepts `addr:`-prefixed keys (validates the stripped null_id, stores the full `addr:<null_id>`). Fixes "DHT lookup failed" / relay-only fallback for contacts that register an addr record.

### Proof-of-Work Tuning
- **`ADDR_POW_DIFFICULTY` 12 → 8** (Argon2id 1 MB ≈ 11 ms/hash → ~3 s at difficulty 8 vs ~45 s at 12, which looked hung).
- **Wall-clock bound on `pow_solve`** — 30 s hard cap returning `PowError::Timeout` instead of spinning until `max_attempts` (10 M) is exhausted. Defensive against future difficulty regressions.

### Address Re-Registration (stale sequence)
- **`dht_register_addr_record` now uses a real monotonic timestamp `seq`** instead of hardcoded `0`. After an IP/port change, re-registration previously sent `seq=0 == existing 0`, so the DHT store rejected it with `stale sequence`. Same fix applied to the reflector/bot earlier. Verified live: listener re-registration on all 3 seeds succeeds with zero `stale sequence` warnings.

### Cleanup
- Removed dead `dht_get_addr_record` from the client and its orphaned tail.
- Removed now-unused PIR imports from the client send/lookup path.
- Removed leftover `[DBG]` read instrumentation.

### Relay mailbox purge (FIX)
- **`eva read` no longer prints `Relay purge warning: invalid JSON: missing field msg_type`** — the client was sending `relay-purge` with the wrong field name (`"type"` instead of `"msg_type"`) and the relay had no `relay-purge` handler at all (request hit the `unknown message type` default). Added a real `relay-purge` handler in `add-relay` that bulk-deletes all mailbox entries for the requester (in-memory + SQLite) after the same ML-DSA-87 signature / null_id / replay / freshness checks used by `relay-fetch`, returning `relay-purge-ack`. The client now emits `relay-purge` with the correct `msg_type` and parses the ack's `payload.accepted`. Deploy the patched relay to all 3 relay servers for the warning to clear.

### Files Changed
- `crypto/src/lib.rs` — `RatchetState.self_mode` + `new_self()`, `decrypt_first`, fixed-key chain logic, `simple_decrypt`/`decrypt_message` self-mode guards.
- `crypto/Cargo.toml` — added `generic-array = "0.14"` (typed `Nonce<U12>` for `simple_decrypt`).
- `client/src/main.rs` — self-message send/reuse path, `relay_fetch_all` returns sender NID/FP, `relay_decrypt_message` self-reuse + first-message routing, `dht_lookup(addr:)`, `dht_register_addr_record` timestamp seq, dead code removed.
- `dht-core/src/dht_node.rs` — `handle_put` accepts `addr:` keys.
- `protocol/src/constants.rs` — `ADDR_POW_DIFFICULTY = 8`.
- `protocol/src/pow.rs` — 30 s wall-clock bound + `PowError::Timeout`.
- `bot/src/main.rs` — real-IP advertisement, `publisher_verifying_key`, timestamp seq.
- `desktop-ui/dist-electron/add-desktop_0.2.0_amd64.deb` — rebuilt with fresh CLI binary.

## 0.3.14 — Post-Quantum Crypto & Desktop Fixes (2026-07-08)

### Post-Quantum Cryptography (ML-DSA-87 / ML-KEM-1024)

- **New `add-crypto-pq` crate** — Post-quantum cryptography module implementing:
  - **ML-DSA-87 (FIPS 204)** — Digital signatures replacing Ed25519/GPG across ALL signing operations:
    - DHT registration (`dht-put` envelopes)
    - Relay store/fetch (`relay-store`, `relay-fetch`, `relay-ack`, `relay-purge`, `relay-read-receipt`, `relay-delete`)
    - P2P hello/hello-ack authentication
    - Reflector bot DHT registration
  - **ML-KEM-1024 (FIPS 203)** — Key encapsulation for all E2E encryption, wrapping existing `add-crypto::kyber` implementation
  - `PqKeyPair` unified type combining both signature and KEM key pairs
  - Proper error handling with `PqError` enum (base64 decode, ML-DSA, ML-KEM, add-crypto errors)
  - Available features: `sign`, `verify`, `encapsulate`, `decapsulate`, `generate` for both ML-DSA-87 and ML-KEM-1024

### Complete GPG/Ed25519 Removal

- All Sequoia OpenPGP GPG signing/verification removed from client, relay, DHT core, and reflector
- ML-DSA-87 signing keys replace GPG certificates for all identity operations
- TOFU (Trust On First Use) uses ML-DSA-87 verifying keys (base64-encoded) instead of armored GPG certs
- Relay `cert_cache` → `ml_dsa87_verifying_key_cache` (fingerprint → base64 verifying key)

### Desktop App Fixes

- **CLI binary spawn (ENOENT)** — Embedded `eva` binary via `electron-builder.json` `extraResources` (bundles 11.4 MB binary at `/opt/Add Desktop/resources/eva`)
- **Command name mismatch** — Fixed IPC handler: `check-contact-status` → `contact-status` (matches CLI subcommand exactly)
- **PID check logic** — Moved check AFTER `Args::parse()`; now only blocks `listen` subcommand if DIFFERENT process holds PID file (non-listen commands overwrite PID file)
- **Debian package verified** — 103 MB .deb with embedded binary confirmed via `dpkg -c`

### Reflector Bot & DHT Registration

- **Multi-bootstrap registration** — Reflector now registers `addr:NN-UFtv-8fHu` to ALL 3 bootstrap servers (eu.gnoppix.org, us.gnoppix.org, asia.gnoppix.org) in parallel with PoW difficulty 8
- **DHT addr: prefix validation** — Fixed `validate_null_id()` in `crypto_helpers.rs` to strip `addr:` prefix before NN-XXXX-XXXX format check
- **Rustls crypto provider** — Added `CryptoProvider::install_default(default_provider())` at startup (required by rustls 0.23+)
- **Removed relay polling from reflector** — Relay `relay-fetch` requires ML-DSA-87 signed requests; reflector now handles direct P2P only (always-online service)
- **Direct P2P echo** — Reflector echoes messages with "🤖 [Reflector Echo]: " prefix via direct P2P connection
- **Fallback to relay** — If sender is offline, reflector delivers echo message to relay via `relay-store`

### Files Changed

- `crypto-pq/Cargo.toml` — New crate with ml-dsa, ml-kem, add-crypto dependencies
- `crypto-pq/src/lib.rs` — Re-exports: signature, kem, keys, error modules
- `crypto-pq/src/signature.rs` — ML-DSA-87 sign/verify wrappers
- `crypto-pq/src/kem.rs` — ML-KEM-1024 encapsulate/decapsulate (wraps add-crypto::kyber)
- `crypto-pq/src/keys.rs` — PqKeyPair, MlDsa87KeyPair, MlKem1024KeyPair types
- `crypto-pq/src/error.rs` — PqError with From impls for all error types
- `desktop-ui/electron/main.js` — CLI path resolution (env, packaged, dev, fallback) + IPC handler fix
- `desktop-ui/electron-builder.json` — extraResources for binary bundling
- `client/src/main.rs` — PID check after arg parse, listen-only blocking, ML-DSA-87 for all signing
- `dht-core/src/crypto_helpers.rs` — validate_null_id accepts addr: prefix, ML-DSA-87 verification
- `bot/src/main.rs` — Registers to all 3 bootstraps eu/asia/us, rustls provider init, P2P only
- `bot/src/config.rs` — Removed relay_urls config (reflector is P2P only)
- `Cargo.toml` (workspace) — Added crypto-pq to members
- `desktop-ui/dist-electron/add-desktop_0.2.0_amd64.deb` — Updated package with embedded binary

## 0.3.12 — Reflector Bot (2026-07-06)

### New Features

- **Reflector Bot (`add-reflector`)** — Standalone echo bot for latency testing and protocol verification
  - Headless client that reflects messages back to sender
  - TTL inheritance: echo messages use sender's TTL setting
  - E2E read receipt: sends `p2p-receipt` on receipt (Double Check ✅✅)
  - Loop prevention: drops messages from `NN-B0T-REFL` or known bot prefixes
  - Zero-footprint storage: in-memory SQLite with auto-cleanup after TTL expires

- **Default Contact Integration**
  - `NN-B0T-REFL` automatically added during `eva init`
  - Desktop UI shows "🤖 Reflector Bot" in contact list for testing
  - Send any message to test end-to-end delivery latency

### Files Changed

- `bot/Cargo.toml` — New crate with tokio, clap, sqlx dependencies
- `bot/src/main.rs` — CLI entry with --config, --prefix, --ttl, --once flags
- `bot/src/config.rs` — BotConfig with ReflectorConfig and NetworkConfig
- `bot/src/message_store.rs` — Volatile in-memory store with TTL cleanup
- `client/src/main.rs` — Added Reflector Bot as default contact
- `desktop-ui/src/store/chatStore.ts` — Auto-add Reflector Bot to contacts

### Usage

```bash
# Build
cargo build -p add-bot

# Run continuously
./target/debug/add-reflector

# Single cycle (testing)
./target/debug/add-reflector --once
```bash
# Send test message
eva send NN-B0T-REFL "hello"
```

## 0.3.13 — Dark/Light Theme (2026-07-07)

### New Features

- **Dark/Light Theme Toggle** — ThemeToggle component in sidebar header
  - Moon icon (🌙) for light→dark, Sun icon (☀️) for dark→light
  - Persists preference in localStorage via Zustand persist middleware
  - Tailwind CSS dark mode with `class` strategy

- **Theme Colors**
  - Light mode: Background #F2F2F7, sidebar #FFFFFF, bubbles #007AFF / #E9E9EB
  - Dark mode: Background #121212, sidebar #1E1E1E, bubbles #0A84FF / #2C2C2E

### Files Changed

- `desktop-ui/tailwind.config.js` — Added `darkMode: 'class'`, light/dark color palettes
- `desktop-ui/src/store/themeStore.ts` — Zustand store with system/light/dark support
- `desktop-ui/src/components/sidebar/ThemeToggle.tsx` — Toggle button with 3-state cycle (system→light→dark)
- `desktop-ui/src/components/sidebar/SidebarHeader.tsx` — Integrated ThemeToggle
- `desktop-ui/src/App.tsx` — Added theme initialization on mount
- `desktop-ui/src/index.css` — Added dark mode scrollbar styles
- `desktop-ui/src/i18n/index.ts` — i18next initialization for 5 languages
- `desktop-ui/src/main.tsx` — i18n import added
- `desktop-ui/package.json` — Added i18next dependencies

### i18n Languages

- English (en), German (de), Spanish (es), Japanese (ja), French (fr)
- Strings accessible via `t('ui.sidebar.settings')`, etc.
- Language detector uses localStorage → navigator fallback

### Usage

Click the moon/sun icon in the sidebar header to toggle themes. Preference saves automatically.

## 0.3.11 — ACS2.6 Compliance (2026-07-03)

### Hardware-Bound Key Hierarchy (Part III.1)
- **Argon2id + HKDF-SHA512** — New `crypto/src/hardware_keys.rs` with `RootSecret`, `IdentityRootKey`, `HardwareKeyManager`
- **HSM fallback stub** — Production-ready interface for TPM/TEE/StrongBox integration
- **Per-session key separation** — Ratchet root, CBNP cover, sealed sender, delivery token, auth HMAC all derived from identity root

### Edge-Core Architecture (Part II.1)
- **NodeRole enum** — `Core` (stationary, unmetered, full routing) vs `Edge` (mobile, battery-constrained, leaf-only)
- **NetworkState enum** — `Unrestricted` (Wi-Fi/charging), `Metered` (cellular normal), `Tactical` (critical low data)
- **TrafficBudget** — Adaptive cover rate (0.1 PPS unrestricted, 0 metered/tactical), burst multipliers, mixnet/push toggles
- **CLI flags** — `--role core|edge`, `--network-state unrestricted|metered|tactical`

### Coordinated Baseline Noise Protocol (Part V.1)
- **Global epoch synchronization** — All nodes align to 2024-01-01 UTC reference epoch
- **Coordinator beacons** — `is_coordinator` flag for timing beacon broadcast
- **Slot-aligned cover traffic** — ±10% jitter within coordinated slots, deterministic packet content
- **Coordinated packet format** — Slot number embedded for verification

### Hardened Subspaces (Part V.3)
- **LFENCE/DSB+ISB speculation barriers** — x86_64 `lfence`, ARM `dsb sy` + `isb`, fallback compiler fence
- **Hardened zeroing** — `secure_zero_memory_hardened()` with pre/post speculation barriers
- **Guard pages + mlock** — Existing `GuardedKeyMaterial` enhanced with speculation mitigation

### Verification
- All 37 crypto tests + 12 relay tests pass
- Release binary verified against production bootstrap/relay infrastructure (3/3 online)

## 0.3.10 — Multi-Relay Failover & Multi-Bootstrap Registration (2026-07-03)

### Multi-Relay Failover
- **Parallel relay fetch** — `eva read` now queries ALL configured relay servers in parallel and deduplicates messages by SHA-256 hash of plaintext
- **Fastest relay selection** — `eva send` probes all relays concurrently (5s timeout) and uses the first to respond
- **Purge from all relays** — After successful read, mailbox is purged from ALL connected relays
- **Configurable via CLI** — `--relay wss://relay1,ws://relay2,...` or auto-discovered via DNS SRV (`_eva-relay._tcp.gnoppix.org`)

### Multi-Bootstrap Registration
- **Register with all bootstrap servers** — `eva register-all-bootstraps` registers identity with ALL 3 bootstrap servers in parallel (solves PoW for each)
- **Check registration status** — `eva check-register` queries all bootstrap servers in parallel and shows per-server status table
- **Default bootstrap servers** — `bootstrap-us.gnoppix.org`, `bootstrap-eu.gnoppix.org`, `bootstrap-asia.gnoppix.org` (via DNS SRV or hardcoded fallback)
- **Both bootstrap and relay use `/ws` path** — Consistent WebSocket path across all configs

### Changes
- Added `select_fastest_relay()` and `relay_fetch_all()` in client
- Added `discover_all_servers()` returning all bootstrap + relay URLs
- Added `Commands::RegisterAllBootstraps` and `Commands::CheckRegister` CLI commands
- Updated `dht_get()` for registration status checking
- Updated client default bootstrap URLs to include `/ws` path

## 0.3.11 — CBNP Cover Traffic & Mix Routing (2026-07-03)

### Privacy Enhancements
- **CBNP Cover Traffic on Federation Channels** — When `--cbnp-enabled` is set (default), relay peers send synthetic cover packets after real messages on WebSocket federation connections. This obscures timing correlation between relays.
- **Mix Routing Random Delays** — Core relays (`--allow-relay`) now apply random delays (1-60 seconds) before processing relay-forward requests, breaking timing correlation between sender and recipient.
- **Incoming Cover Traffic Detection** — Federation receivers silently drop cover traffic packets (detected via `0xC0` tag prefix), making them indistinguishable from noise.

### Changes
- Added `cover_session` and `cover_queue` fields to `PeerInfo` struct in relay state
- Modified `connect_to_peer` to send cover packets after real federation messages
- Added `MIX_MIN_DELAY_SECONDS` and `MIX_MAX_DELAY_SECONDS` constants for mix routing
- Added `cbnp_enabled` field to `RelayState` for feature gating
- Added `#[derive(Debug)]` to `CbnpSession` in crypto crate
- All 12 relay tests pass

## 0.3.10 — Message Deletion Feature (2026-07-03)

### New Features
- **`eva delete <position>` command** — Users can now delete their stored messages by position number shown in `eva read` output. Position 1 refers to the newest message (top of the list).
- **Position numbers in read output** — The stored messages list now shows position numbers `[1]`, `[2]`, etc. for easy deletion reference.
- **Usage hint** — After listing stored messages, a helpful hint shows: `(use 'eva delete <position>' to delete a message)`

### Desktop UI
- **Electron desktop client scaffold** — Signal-inspired split-pane interface (30% sidebar, 70% chat)
- **Components**: Sidebar, ChatPane, MessageList, MessageInput, ConversationRow
- **State**: Zustand store with activeConversationId, conversations, messages, searchQuery
- **Build**: `cd desktop-ui && npm install && npm run dev`
- **Web testing**: Vite dev server at http://localhost:5173

## 0.3.9 — Bidirectional E2E Encryption & Wire Format Fix (2026-06-29)

### Critical Fixes
- **Bidirectional Double Ratchet wire format fix** — `encrypt_message()` in `crypto/src/lib()` wrote the 2-byte Kyber ciphertext length BEFORE the Kyber CT (`nonce + aes_ct + 2-byte-len + kyber_ct`), but `decrypt_message()` read it from the END of the body. This caused `kyber_len` to be parsed as random bytes from the Kyber CT itself, always exceeding body length, so the receiver fell back to `simple_decrypt` which doesn't mix in the Kyber shared secret — resulting in AES-GCM decryption failure in the reverse direction. Fixed by moving the 2-byte length field to the END: `nonce + aes_ct + kyber_ct + 2-byte-len`. This enables full bidirectional E2E messaging (initiator→responder AND responder→initiator).

### E2E Verification
- **Full bidirectional E2E test verified** — amu@mac ↔ debian@us via relay at root@is, both directions decrypting successfully across multiple ratchet hops.

### Test Coverage
- Added `test_bidirectional_ratchet_roundtrip` regression test — exercises 4-message round-trip (first message via simple_decrypt + 3 subsequent messages via Kyber-mixed decryption).
- Total: 32 crypto tests pass (was 31 in 0.3.8), 16 protocol tests unchanged.

## 0.3.8 — TOFU GPG Verification Fix (2026-06-28)

### Fixes
- **Relay GPG TOFU verification fixed** — `verify_gpg_detached()` now caches certificates BEFORE signature verification (previously cached after, causing verification to fail on first fetch). This enables seamless P2P message delivery without pre-registration.
- **Signature UTF-8 handling corrected** — Changed `String::from_utf8_lossy()` to `String::from_utf8()` for proper signature validation. Armored signatures are already UTF-8-safe; lossy conversion could corrupt them.

### Data Migration Required
- No migration required. The fix is in relay-side verification logic.

## 0.3.7 — Auto-Discovery, Armored Certs, Register & PID Lock (2026-06-27)

### New Features
- **DNS SRV auto-discovery** — Client now discovers bootstrap and relay servers via `_eva-bootstrap._tcp.gnoppix.org` and `_eva-relay._tcp.gnoppix.org` SRV records. Falls back to hardcoded defaults, then localhost. CLI `--seed`/`--relay` flags still override.
- **Identity override confirmation** — `eva init` now checks for existing identity and requires typing `yes` before destroying it.
- **`eva register` subcommand** — Explicitly registers identity with the bootstrap DHT (solves PoW at difficulty 16). Needed when init was run without bootstrap connectivity.
- **PID file lock** — `~/.add/add.pid` prevents multiple instances from racing on the same SQLite DB and GPG home. Detects stale locks and checks if PID is alive.

### Fixes
- **GPG cert serialization: binary → ASCII-armored** — `generate_identity()` was writing raw binary OpenPGP data to `own_cert.asc`, corrupting it via `String::from_utf8_lossy()`. Now uses `cert.as_tsk().armored().serialize()` for proper ASCII output. Existing corrupt certs are detected with a clear error message.
- **Corrupt cert detection** — `load_cert()` now detects binary/null-byte files and suggests `rm -rf ~/.add/gnupg && eva init`.
- **rustls CryptoProvider** — Added `rustls::crypto::ring::default_provider().install_default()` to fix panic on `wss://` connections.
- **Both bootstrap and relay use `/ws` path** — Consistent WebSocket path across all configs (fallback + SRV discovery).

### Breaking Changes (data)
- Existing `~/.add/gnupg/own_cert.asc` files from before v0.3.7 are **corrupt** (binary data). Users must delete `~/.add/gnupg/` and re-run `eva init`.

## 0.3.3 — Static Build: Sequoia crypto-rust Backend (2026-06-27)

### Fixes
- **Sequoia OpenPGP now uses pure-Rust crypto backend** (`crypto-rust` instead of `crypto-nettle`). This eliminates the `libnettle.so.8` shared library dependency, fixing `undefined symbol: nettle_ocb_set_key` errors on systems with older Nettle versions.
- **crypto-utils crate fixed** — Changed direct `sequoia-openpgp = "2"` to `workspace = true` so all crates use the same backend (prevented "Multiple cryptographic backends selected" build error).

### Trade-offs
- `crypto-rust` is marked **experimental** by Sequoia. For a censorship-resistant messenger, portability (no C deps) is more important than the "stable" label on the Nettle backend. Variable-time crypto is allowed for non-constant-time RSA operations.

## 0.3.2 — Client SQLite Fix & rustls Provider (2026-06-27)

### Fixes
- **Client SQLite connection fixed** — Same `sqlite://{path}?mode=rwc` fix as relay (0.2.9). Client's `MessageStore::open()` now auto-creates the database file.
- **rustls CryptoProvider installed** — Client now calls `rustls::crypto::ring::default_provider().install_default()` at startup. Without this, any `wss://` connection panicked with "Could not automatically determine the process-level CryptoProvider".

## 0.3.0 — Client --seed/--relay Flags & Remote Testing (2026-06-27)

### Features
- **`--seed` flag** — Override default bootstrap URL (`ws://127.0.0.1:9001`) from CLI
- **`--relay` flag** — Override default relay URL (`ws://127.0.0.1:8765`) from CLI
- Enables remote testing against deployed servers: `eva --seed wss://bootstrap.example.com --relay wss://relay.example.com/ws status`

### Fixes
- **Relay SQLite connection fixed** — Changed URL from `sqlite:path` to `sqlite://path?mode=rwc` so sqlx 0.8 auto-creates DB file
- **Relay auto-creates gpg-home directory** — If `--gpg-home` directory doesn't exist, it's created automatically instead of falling back to a literal `~` path.
- **Relay `--db-path` flag added** — Explicit control over SQLite database file location, independent of `--gpg-home`.

## 0.2.8 — TLS Proxy Detection & Bootstrap Auto-Key Generation (2026-06-27)

### New features
- **Bootstrap `--tls-cert` and `--tls-key` flags** — Direct TLS mode for bootstrap when not behind nginx
- **Bootstrap `--allow-no-key` behavior fixed** — `--allow-no-key` no longer generates Kyber keys (dev/test only uses random ID)
- **Bootstrap auto-generates Kyber-1024 identity** — When no GPG key exists and `--allow-no-key` not set, creates `~/.add/kyber_keypair.json` for stable Null ID
- **Host-based TLS detection** — TLS warning only appears when listening on external IP without certs (silenced for `127.0.0.1`/`0.0.0.0` proxy mode)
- **Relay TLS warning suppressed in proxy mode** — When `--host 127.0.0.1` or `--host 0.0.0.0`, TLS warning is silent since nginx handles TLS termination

### Fixes
- **Makefile `target-cpu=native` removed** — Fixes "Illegal instruction" errors on Intel i7-1068NG7 (Ice Lake) CPUs

### Dependencies
- `ml-kem = "0.3"` added to bootstrap crate

## 0.2.7 — Relay Mailbox Persistence (2026-06-26)

### Security fixes
- **Relay mailbox persistence (C5)** — Relay now stores mailbox entries in SQLite (`mailbox.db`, 0o600). Messages survive relay restart instead of being lost on process exit. Each row stores opaque ciphertext blobs (already encrypted by sender via DoubleRatchet), so stored data is always encrypted. In-memory cache preserved for fast reads; SQLite is source of truth.

### Test coverage
- All 12 relay tests pass (unchanged behavior — SQLite is additive)

## 0.2.6 — P2P Handshake Authentication & Relay Federation Enforcement (2026-06-26)

### Security fixes
- **P2P initiator: verify hello-ack GPG signature** — Previously the initiator signed its hello but never verified the responder's hello-ack. An active MITM could inject a fake hello-ack with their own Kyber key. Now the initiator MUST verify the ack signature and rejects connections with unsigned acks.
- **P2P responder: reject unsigned hellos** — Changed from TOFU-warn to hard reject. Any peer sending a hello without a GPG signature is now disconnected.
- **Relay federation: enforce peer authentication** — `relay-forward` messages now check `peer.authenticated` before accepting. If `shared_secret` is configured, unauthenticated peers get rejected with an error ACK.
- **RelayForward struct: added source_relay_url field** — Receiving relay can now look up the sender's authentication state. Backward compatible (`#[serde(default)]` — older senders get empty string).
- **forward_to_peer: auto-set source_relay_url** — When forwarding, our URL is set so the receiving relay can authenticate us.

### Test coverage
- `test_source_relay_url_defaults_empty` — verifies backward-compatible deserialization
- Updated `test_relay_forward_loop_detection` to include the new field

## 0.2.5 — Memory Zeroization of Secret Buffers (2026-06-26)

### Security fixes
- **DoubleRatchetSession: ZeroizeOnDrop** — `root_key`, `send_chain_key`, `recv_chain_key` now automatically zeroed when session is dropped. Uses `#[zeroize(skip)]` on non-sensitive metadata (fingerprints, sequence numbers).
- **VariantKeypair: ZeroizeOnDrop** — `dec_bytes` (private key seed) zeroed on drop. `variant` and `enc_bytes` (public) skipped.
- **MlKem1024Keypair: automatic zeroization** — `DecapsulationKey` already implements `ZeroizeOnDrop` from ml-kem crate; drop glue clears it when keypair is dropped.
- **DbEncryptionKey: ZeroizeOnDrop** — SQLite encryption key zeroed when `MessageStore` is dropped.
- **Signal handler fix** — SIGINT/SIGTERM now triggers graceful shutdown (allowing Drop impls to run) instead of `std::process::exit(0)` which bypassed zeroization. Added SIGTERM handler for systemd integration.

### Dependencies
- Added `zeroize` (with derive feature) to client crate.

## 0.2.4 — GPG Secret Key Encryption at Rest (2026-06-26)

### New features
- **GPG secret key encryption**: `own_cert.age` stores the Sequoia secret key encrypted with age passphrase encryption (scrypt recipient + XChaCha20-Poly1305 AEAD)
- `generate_identity` prompts for a passphrase during `eva init` (no-echo via `rpassword`); encrypted key written as `~/.add/gnupg/own_cert.age` (0o600)
- Empty passphrase = legacy plaintext (`own_cert.asc`) — backward compatible opt-out
- `load_cert` tries `own_cert.age` first (prompts for password via `rpassword`), falls back to `own_cert.asc` for existing plaintext installs
- Re-running `eva init` with a passphrase removes the old plaintext `own_cert.asc`

### Dependencies
- `age 0.11` (pure Rust, scrypt + XChaCha20-Poly1305)
- `rpassword 7` (cross-platform no-echo TTY password input)

## 0.2.3 — DoubleRatchet Session Persistence & Relay Decryption (2026-06-26)

### New features
- **P2P session persistence**: DoubleRatchet sessions are now saved to the SQLite message store (`ratchet_sessions` table) after creation in both `send_message` and `handle_incoming_connection`
- **Relay message decryption**: `relay_fetch` now decrypts offline messages using persisted DoubleRatchet sessions instead of returning raw ciphertext blobs
- `relay_decrypt_message` parses the relay's `signed_blob` as a `WireEnvelope`, loads the session by sender NID, decrypts the ciphertext, and re-saves updated session state
- Sessions keyed by peer Null ID for both send and receive paths

## 0.2.2 — Nginx TLS Proxy & WSS Support (2026-06-26)

### New features
- **WSS/TLS support**: The smartest implementation here is simpler than the blueprint. You want nginx on :443 terminating TLS, so the bootstrap server stays plaintext on localhost. Three actual code changes needed:

1. **Client wss:// support** — `dht_lookup` and `relay_fetch` currently do `https:// → wss://` string replacement but then connect with plaintext TCP. Now they actually do TLS.
2. **Bootstrap `--advertised-url`** — when behind nginx, the DHT records must advertise `wss://public-domain` instead of `ws://localhost:9001`.
3. **P2P wss:// support** — `connect_direct` now handles both `ws://` and `wss://` schemes.

### Implementation notes
- `tokio-tungstenite` now uses `rustls-tls-native-roots` feature (client + p2p crates) for native wss:// support
- No custom TLS code in any crate — tokio-tungstenite handles TLS via rustls with WebPKI verification
- Nginx handles TLS termination; the daemon binds to `127.0.0.1` and never sees TLS
- `--advertised-url` sets `NodeConfig.advertised_url` in dht-core, which the DHT node uses as its public address
- All 86 existing tests pass

### Documentation
- Added `docs/nginx-proxy.md` — full nginx config with WebSocket upgrade, fallback page, rate limiting

## 0.2.1 — Alias convenience (2026-06-26)

### New features
- **Alias system**: `eva alias <name> <NID>` maps human-readable names to Null IDs
- `eva aliases` lists all configured aliases
- `send`, `chat`, `verify`, `safety-number` now accept alias or raw Null ID
- Alias storage at `~/.add/aliases.json` (0o600 permissions)

## 0.2.0 — First App Ready (2026-06-25)

**Breaking:** Version bump from 0.1.0 → 0.2.0. All first-app blockers resolved.

### Documentation
- Restructured docs: README simplified (10-year-old level), FEATURES.md merged into DEVELOPER.md (technical) + README (general), FAQ de-duplicated

### New features
- **B1 — Guard pages**: `GuardedKeyMaterial` in `crypto/src/secure_mem.rs` — PROT_NONE mmap guard pages around key material, mlock, secure_zero with DSE fence
- **B2 — CBNP cover traffic**: `crypto/src/cbnp.rs` — Poisson-timed exponential inter-arrival dummy packets in relay
- **B3 — DB encryption at rest**: `client/src/main.rs` — AES-256-GCM on ciphertext column; key at `.add/db_key.json` (0o600)
- **B4 — Delivery tokens (Sealed Sender)**: `crypto/src/delivery_tokens.rs` — HMAC-SHA256 HKDF-derived 28-byte anonymous tokens
- **B5 — PIR contact cache**: `crypto/src/pir.rs` — Cuckoo-hashed blind registry for local contact discovery
- **I1 — TOFU peer admission**: `relay/src/main.rs` — Certificate fingerprint pinning with disk persistence
- **I2 — Graceful shutdown**: Ctrl+C signal handlers in client and relay
- **Braid Protocol (SPQR) — library only at 0.2.0**: `protocol/src/braid.rs` — `split_key_to_chunks()` pipelines 1568-byte ML-KEM-1024 keys in 64-byte chunks. (Wired into the live P2P handshake + ratchet in 0.3.16.)
- **In-memory KEM state DB**: `MessageStore::open_in_memory()` — `sqlite::memory:` with ephemeral key for handshake state

### Fixes
- `reconstruct_enc_key()` now takes `key_len` to handle non-aligned key sizes (1568 bytes = 25 chunks)
- `dealloc_guarded` fixed: was using Rust `dealloc()` on mmap'd memory (UB/SIGSEGV); now uses `libc::munmap`

### Stats
- 91 workspace tests (38 crypto + 14 protocol + 17 p2p + 2 braid + 9 dht + 11 relay)
- Binary: 6.9 MB (client), 4.6 MB (relay)
- Deb: 2.4 MB

## 0.1.0 — Initial scaffold (2026-06-24)

- Workspace structure: 8 crates
- Basic P2P protocol, DHT, relay skeleton
- Classical X25519 key exchange (pre-PQ)

## 0.1.0 — Initial scaffold (2026-06-24)

- Workspace structure: 8 crates
- Basic P2P protocol, DHT, relay skeleton
- Classical X25519 key exchange (pre-PQ)

### Security (CRITICAL-2 Fix)
- **CRITICAL-2**: All P2P handshake and message signatures now properly signed with GPG/Sequoia
- **P2P hello**: Now signed with `sign_for_transport()` before sending
- **P2P hello-ack**: Now signed with GPG signature for MITM prevention
- **P2P message**: Now signed with GPG signature authenticating the sender
- **P2P ack**: Now signed to prevent forged acknowledgments
- **relay_fetch**: Fixed to use `relay-fetch` protocol with proper GPG signature
- **dht_lookup**: Now signs `dht-get` requests with our PGP key
- **Signature verification**: Added verification for incoming P2P hello and message signatures
- Empty signatures (`"sig": ""`) eliminated across all wire protocols

### Security (HIGH-3 Fix)
- **relay_fetch**: Fixed protocol mismatch - client now sends `relay-fetch` instead of non-existent `relay-get`
- Added `sender_cert` field to relay-fetch request for TOFU certificate caching
- Added `auth_hmac` field to relay-fetch request for optional HMAC authentication
- Fixed response parsing to use `entries` array instead of incorrect `messages` field

### Security (HIGH-4 Fix)
- **HIGH-4**: Removed plaintext storage from SQLite message database
- Removed `decrypted` field from `StoredMessage` struct and `messages.db` table
- Set `messages.db` file permissions to 0o600 (owner-read/write only)
- Messages now stored encrypted only; plaintext never written to disk

### Security (HIGH-5 Fix)
- **HIGH-5**: Added 0o600 file permissions to sensitive files
- `identity.json` — already had permissions set
- `contacts.json` — now uses 0o600 permissions (was world-readable)
- `own_cert.asc` — now uses 0o600 permissions (contains private key)

### Security (HIGH-6 Fix)
- **HIGH-6**: Implemented relay federation - messages can now traverse between relays
- Added `mpsc` channel to `PeerInfo` for federation message routing
- `connect_to_peer()` now establishes persistent WebSocket connection with sender/receiver tasks
- `gossip_task()` now sends route-advertise messages to peer channels
- `forward_to_peer()` now sends relay-forward messages to peer channels

### Security (CRITICAL-1 Finalization)
- **CRITICAL-1**: Full Kyber-768 key exchange integration into P2P handshake completed
- Added `kyber_enc_key` field to `P2pHello` and `P2pHelloAck` structs
- Updated `build_p2p_hello()` to include peer's Kyber public key
- Updated `build_p2p_hello_ack_signed()` for MITM prevention via GPG signatures
- Client `generate_identity()` now creates persistent Kyber-768 keypair stored at `~/.add/kyber_key.json`
- Client `send_message()` performs Kyber encapsulation and encrypts via `DoubleRatchetSession`
- Client `handle_incoming_connection()` extracts peer's Kyber public key, performs decapsulation, and decrypts via `DoubleRatchetSession`
- Added `encode_enc_key()` and `decode_enc_key()` helper functions in crypto crate for base64 encoding
- All messages now encrypted with Kyber-768 KEM + AES-256-GCM (no plaintext option)

### Changed
- **Sequoia OpenPGP migration (seq1–seq8)**: All GPG operations that previously
  shelled out to the system `gpg` binary are now replaced with in-process
  Sequoia OpenPGP (v2.3.0) operations. This eliminates:
  - Spawning external processes for signing/verification
  - World-readable temp files in /tmp
  - Dependency on GnuPG installation
  - Parsing GPG status output
  Affected crates: protocol, dht-core, crypto-utils, client, bootstrap, relay.
- **DHT signature verification** now uses publisher cert from envelope payload
  (TOFU pinning via cert cache) instead of fingerprint-only verification.
- **Relay signature verification** uses in-process Sequoia with cert cache
  (TOFU on first sight) instead of shelling out to gpg binary.

### Added
- `publisher_cert` field to `DhtPut` and `DhtAddrRecord` payloads for
  in-process signature verification.
- `cert_cache` in `RelayState` for TOFU-based cert caching.

### Removed
- Dependency on GnuPG (gpg binary) — pure Rust OpenPGP now.
- `--gpg-home` CLI argument (replaced by `--cert-dir`).

### Added (earlier)
- **Multi-relay federation** — Relays can now form a federated network with
  gossip-based message forwarding between peers
  - `--peer` CLI argument connects relays to each other (WebSocket)
  - `--peer-file` reads peer URLs from a file
  - `--secret` / `--secret-file` for HMAC-SHA256 peer authentication
  - `--url` to advertise relay URL for gossip
  - Periodic route advertisement (gossip) every 60s
  - `relay-forward` message type with hop count (max 5) and loop detection
  - `route-advertise` / `route-advertise-ack` for route propagation
  - `who-has` query to find which relay serves a Null ID
  - Background gossip task: route advertisement, route expiry (30min), peer health (5min)
  - 11 new unit tests for federation logic (URL parsing, HMAC, routes, nonce replay, loop detection)
- **Client send/read/listen commands** — Full P2P messaging implementation (G1-G3)
  - `send` command: DHT lookup → P2P connection → handshake → encrypted delivery
  - `read` command: relay mailbox fetch → decrypt → display + local storage
  - `listen` command: WebSocket listener for incoming P2P connections with auto-handshake
- **SQLite message persistence** (G5) — Local message store at `~/.add/messages.db`
  - Stores sent, received, and fetched messages with metadata
  - Auto-creates schema on first open
- **Safety number verification** (G6) — Contact verification via deterministic safety number
  - `verify <null_id>` command shows safety number for out-of-band comparison
  - `safety-number <null_id>` command shows your safety number
  - Analogous to Signal's safety number (SHA-256 of sorted fingerprints, formatted as 8 groups)
- **DoubleRatchetSession persistence** (G9) — Sessions survive restarts
  - `serialize()` / `deserialize()` / `save()` / `load()` methods
  - JSON format with 0o600 file permissions
  - Preserves all session state: keys, sequence numbers, pending messages
- **Kyber key persistence** (G10) — Keys survive restarts, DHT address stays stable
  - `save()` / `load()` / `load_or_generate()` methods
  - JSON format with hex-encoded key bytes, 0o600 file permissions
  - Uses `KeyExport::to_bytes()` for canonical byte representation
- **New CLI commands**: `verify`, `safety-number`
- **New dependencies**: `sqlx` (SQLite) in client crate

### Security (Low-severity fixes L1-L7)
- **L1**: GPG temp signature file moved from /tmp to GPG home dir (0o700)
- **L2**: MAX_TOTAL_KEYS enforcement now runs unconditionally (not gated on sig non-empty)
- **L3**: Background task periodically prunes seen_nonces map (prevents memory exhaustion)
- **L4**: Relay `--secret-file` option added (reads secret from file instead of CLI arg)
- **L5**: Removed dead `TRUSTED_CA_FINGERPRINTS` constant with fake placeholder fingerprint
- **L6**: `validate_fingerprint()` now accepts 32 or 40 hex chars (GPG v3 + v4)
- **L7**: Addr-record writes now require PoW (ADDR_POW_DIFFICULTY = 12)

### Security (Medium-severity fixes M1-M8)
- **M1**: Removed unused `sha2` dependency from crypto-utils
- **M2**: Relay `--peer` argument now validated before use
- **M3**: Relay shared secret read from file with 0o600 permissions
- **M4**: DHT MAX_TOTAL_KEYS check enforced for all puts (defense-in-depth)
- **M5**: Relay rate limiter shared state fixed
- **M6**: P2P handshake includes server challenge (prevents replay)
- **M7**: DHT GET operations now rate-limited per-IP (prevents key enumeration)
- **M8**: Bot log file size limited to 10 MiB with rotation

### Security (Medium-severity fixes G7-G10)
- **G7**: Fingerprint sanitized before filesystem use to prevent path traversal (import_pubkey)
- **G8**: Session serialization security note added (pending ciphertext in JSON)
- **G9**: Rate limiter max buckets limit (100k) to prevent memory exhaustion under DoS
- **G10**: PoW parameters validated (nonce range, difficulty) before hashing in handshake

### Security (High-severity fixes H1-H7)
- **H1**: Relay HMAC timing-safe comparison (prevents timing attacks)
- **H2**: DHT bootstrap TOFU pin cache hardened
- **H3**: Relay message queue bound enforced (prevents memory DoS)
- **H4**: Relay envelope timestamp freshness check (±300s window)
- **H5**: DHT put handler signature verification before storage
- **H6**: Relay connection limit per IP enforced
- **H7**: DHT bootstrap cert validation includes trusted domain check

### Security (Critical fixes C1-C6)
- **C1**: TLS 1.3 enforced for bootstrap connections
- **C2**: DHT bootstrap cert pinning enforced
- **C3**: Relay secret zeroed from memory after use
- **C4**: Relay --secret-file option (secret not in process list)
- **C5**: DHT bootstrap TOFU grace period implemented
- **C6**: TLS acceptor properly configured for DHT WebSocket server

### Documentation
- **G4**: Kademlia DHT routing documented as intentional (centralized seed model)
- **G7**: Relay federation documented as intentional (single-relay model)
- **G8**: I2P transport documented as intentional (Tor-first, I2P future)

### Changed
- **Test count**: 44 → 45 (new Kyber key persistence roundtrip test)
- **Client header comment**: Updated with G1-G5 implementation status
- **Constants**: `ADDR_POW_DIFFICULTY` (12) added for addr-record PoW

