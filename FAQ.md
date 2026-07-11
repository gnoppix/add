# Add FAQ

Common questions about Add security, encryption choices, and trade-offs.

---

## What is CBNP (Coordinated Baseline Noise Protocol)?

CBNP generates synthetic "cover traffic" to hide real message patterns from network observers. Without cover traffic, an attacker can see when you're active vs idle, and correlate message timing to guess who talks to whom.

**How it works:**
- Each relay generates fake packets with the same size distribution as real messages
- Packets are indistinguishable from real traffic (same format, encryption-like payload)
- A special tag (`0xC0` prefix) lets recipient relays identify and silently drop them
- On federation channels, cover packets are sent after real messages to obscure timing

**Example:**
```
Time:  T0     T1     T2     T3     T4     T5
Real:      [M1]           [M2]             
Cover:  [C1] [C2]   [C3] [C4] [C5] [C6]

Without CBNP:   Attacker easily sees M1 at T1, M2 at T4
With CBNP:      Attacker sees constant stream but cannot distinguish real from cover
```

CBNP is enabled by default (`--cbnp-enabled`). On mobile or metered connections, use `--cbnp-enabled=false` to save bandwidth.

---

## How does multi-relay failover work?

Add connects to multiple relay servers simultaneously for resilience:

**On send (`add send`):**
- Probes all configured relays in parallel (5s timeout)
- Uses the **fastest responding relay** for message delivery
- Falls back sequentially if all timeout

**On read (`add read`):**
- Queries **ALL relays in parallel** for messages
- Deduplicates messages by SHA-256 hash of plaintext
- Purges mailbox from **ALL relays** after successful delivery

**Configuration:**
```bash
# Comma-separated list
add --relay wss://relay-us.gnoppix.org/ws,wss://relay-eu.gnoppix.org/ws,wss://relay-asia.gnoppix.org/ws send @alice "hello"

# Or auto-discover via DNS SRV
add send @alice "hello"
```

---

## How does multi-bootstrap registration work?

Your identity is registered on ALL bootstrap servers for maximum discoverability:

**Commands:**
```bash
# Register with all 3 bootstrap servers in parallel
add register-all-bootstraps

# Check registration status on all servers
add check-register
```

**Default bootstrap servers:**
- `bootstrap-us.gnoppix.org`
- `bootstrap-eu.gnoppix.org`
- `bootstrap-asia.gnoppix.org`

**Auto-discovery via DNS SRV:**
```
_eva-bootstrap._tcp.gnoppix.org
_eva-relay._tcp.gnoppix.org
```

Both bootstrap and relay servers use the `/ws` WebSocket path consistently.

---

## Why is Add different from Signal?

Signal protects your messages too, but it still uses classical encryption (X25519) for most operations. The post-quantum protection only happens at the initial handshake. Add uses ML-KEM-1024 (the strongest post-quantum standard) for EVERY message. Even if someone records all traffic now and builds a quantum computer in 20 years, they still can't decrypt it.

Also, Signal routes messages through Google's servers. Add connects you directly to your friends — no company in the middle.

To clarify: Signal was a highly effective service, but it failed to adapt to changing times.

This stall may well be due to the increasing commercialization of the platform. As laws have shifted, Signal—like any other centralized service provider—has become subject to government surveillance orders. Of course, this wouldn't be an issue if messages were fully post-quantum encrypted, ensuring that only the users themselves held their private keys and passwords.

This raises the question of how the EU views such an outdated solution, which is now in urgent need of an architectural overhaul. This limitation is likely why Signal is not approved by the US government for highly sensitive communications (after all, we know how easily centralized, non-quantum-resistant messages can be intercepted and harvested).

Just as we see in the crypto space, the absolute key to ensuring a service remains free from external influence is decentralization. If one node shuts down, other nodes should automatically be spun up and operated by the users themselves. Because the messenger is free, everyone who utilizes it naturally becomes a structural part of the network. More than fair. 


Ultimately, how do you guarantee that messages can never be decrypted? Through uncompromising post-quantum encryption, where only the end users hold their private keys and (strong) passwords on a decentralized infrastructure.

See: https://github.com/gnoppix/Add/blob/main/gnoppix_vs_signal.md


---

## Why should I care about post-quantum encryption?

Newer and faster computers (including future quantum computers) will be able to break today's encryption. If someone records internet traffic now, they can decrypt it later when powerful computers exist. Add uses encryption that resists even quantum computers.

---

## What is a Null ID and is it private?

Your Null ID (like `NN-XXXX-XXXX`) is a short code derived from your public key. It's safe to share — it doesn't reveal your identity, but it lets people find and message you. Think of it like a phone number that only you can answer.

---

## Do I need to trust any server?

No. The bootstrap seed server only helps you find your friend's address — it never sees your messages. The relay (if used) stores encrypted blobs it cannot read. All encryption and decryption happens on your device.

---

## What if someone steals my phone?

Your keys are stored with 0o600 permissions (only your user can read them). For mobile devices, Add supports biometric access lifecycle — keys are scrubbed when the app goes to background or the device locks. This is a future enhancement.

---

## Can the government read my messages?

No. The content is encrypted with ML-KEM-1024 + AES-256-GCM. The government would need to break the math behind these algorithms, which is believed to be impossible even for supercomputers.

What they CAN see (if you don't use Tor): that you're running Add, when you connect, and how much data you transfer. Tor hides this.

---

## Why is there no group messaging yet?

Post-quantum group messaging requires ML-DSA-87 signing (PQ-Sender Keys), which is more complex to implement. It's planned in the ACS2.6 specification but not yet implemented. For now, Add supports 1-to-1 messaging only.

---

## What happens if I lose my identity?

Run `add export` to save your public key. Share it with contacts so they can still verify your identity. Your private key stays on your device — if you lose the device, you need to generate a new identity and have contacts verify the new one.

---

## How do I know someone isn't impersonating my contact?

Add shows a **safety number** — a deterministic code derived from both parties' fingerprints. Compare it out-of-band (in person, voice call, PGP-signed email). If the numbers match, no one is intercepting your communication.

---

## Why I2P not supported?

Add follows a Tor-first approach. I2P support is planned but requires additional dependencies and architectural changes. For now, Tor provides IP-level privacy when enabled.

---

## Why Argon2id instead of SHA-256 for proof-of-work?

SHA-256 hashcash is trivially GPU-accelerated. A single RTX 4090 can compute ~10 billion SHA-256 hashes/second. Argon2id is memory-hard: each instance requires 16MB of RAM. A 24GB GPU can only run ~1,500 parallel instances, each taking ~0.5s. This reduces botnet throughput by ~500,000x.

---

## What's the centralized seed model? Why not full Kademlia?

Instead of full Kademlia DHT routing (which requires complex routing table maintenance), Add uses centralized bootstrap seeds as authoritative directories. This is:
- Simpler to implement and audit
- More reliable (no routing table maintenance, no lookup latency)
- Sufficient for current scale

Full Kademlia routing is a future enhancement.

---

## How does the relay federation work?

Multiple relays can form a network where messages route between them. Each relay maintains a list of which Null IDs it serves locally and which are reachable via peer relays. Messages can traverse up to 5 relay hops with loop detection. Peer connections are authenticated with HMAC-SHA256 using a shared secret.

---

## What data does the relay see?

The relay sees: sender Null ID, receiver Null ID, connection timestamps, and message size. It does NOT see message content (encrypted before leaving the client). Route through Tor to obscure IP metadata.

---

## What happens when I receive a message while offline?

When you're offline, messages are stored encrypted on the relay. When you run `add read`, the client fetches those offline messages and decrypts them using your persisted Double Ratchet sessions. The session state is updated after decryption, so future messages from the same contact continue to work correctly — including replies in the other direction.

**Bidirectional relay messaging:** Starting from v0.3.9, both directions of the Double Ratchet work through the relay. If Alice sends Bob a message while Bob is offline, Bob can later reply (also while Alice is offline) and both sides decrypt correctly when they come online.

If this is your first conversation and the session was created when the message arrived (e.g., someone sent you a message and you received it via relay before ever connecting directly), the session has already been initialized and decryption works transparently.

---

## Is my GPG private key stored safely on disk?

Yes. Starting from v0.2.4, your GPG secret key is encrypted at rest using age passphrase encryption (scrypt + XChaCha20-Poly1305). You set the passphrase during `add init`. On startup, the client prompts you to enter it before the key is decrypted into memory.

If you prefer not to set a passphrase, press Enter at the prompt — the key will be stored as plaintext (previous behavior). Backward compatibility with existing plaintext `own_cert.asc` files is preserved.

---

## I get "corrupt identity file detected" — what do I do?

This error means your `~/.add/gnupg/own_cert.asc` file was written by a version before v0.3.7 in a buggy way (binary data was written as text, corrupting it). Fix it:

```bash
rm -rf ~/.add/gnupg
./add init
```

The new init will create a properly formatted ASCII-armored cert file.

---

## I get "recipient not found in DHT" — what do I do?

The recipient's identity was never registered with the bootstrap DHT. This happens when:
- The recipient ran `add init` while the bootstrap was unreachable
- The recipient is using a different bootstrap server than you

Fix: On the recipient's machine, run:

```bash
./add register
```

This explicitly registers the identity with the bootstrap DHT. After registration, you can send messages to them.

---

## How does message delivery work?

Add uses a two-tier delivery system: **direct P2P** when the recipient is online, and **relay mailbox** when they're offline.

### Direct P2P delivery (primary)

When you send a message:

1. The recipient's address is looked up in the DHT (bootstrap seed).
2. A direct WebSocket connection is established to the recipient's P2P listener.
3. A handshake exchanges Kyber-1024 public keys and proves identity via GPG signatures.
4. Messages are encrypted with the Double Ratchet algorithm (ML-KEM + AES-256-GCM) and sent directly.
5. The recipient decrypts immediately and sends back two confirmations:
   - `p2p-ack` — transport-level confirmation (message received)
   - `p2p-receipt` — cryptographic E2E confirmation (message decrypted and read)

You see `"Message delivered successfully!"` on ack, and `"Message READ by peer at HH:MM:SS [E2E confirmed]"` on receipt.

### Relay mailbox (fallback)

If the recipient is offline or unreachable via P2P, the message is stored encrypted on the relay:

1. The sender stores the encrypted message in the recipient's relay mailbox.
2. When the recipient comes online and runs `add read`, the client fetches all stored messages.
3. Messages are decrypted using the persisted Double Ratchet session.
4. After successful fetch and decryption, the client sends a `relay-purge` command to delete all messages from the mailbox. This prevents stale ciphertext from accumulating.

### Delivery confirmation levels

|| Level | What it proves | How it's verified |
||---|---|---|
|| Relay stored | Message reached the relay | Relay returns `"ok"` |
|| P2P ack | Message reached the peer over WebSocket | Signed `p2p-ack` received |
|| P2p-receipt | Peer decrypted the message | Signed `p2p-receipt` with recipient's GPG key |

### Edge-core relay mode

Relays can run in two modes:

- **Core mode** (`--allow-relay`): accepts and forwards messages between other relays (federation transit). This is the default for server-side relays.
- **Edge mode** (default, no `--allow-relay`): only serves its own local mailboxes. Refuses to forward messages on behalf of other relays. This is appropriate for mobile or battery-powered nodes running a local relay.

Edge mode prevents mobile nodes from being used as transit points in the relay federation, saving battery and bandwidth.

### How clients discover the port:

1. Relay registration - When you start relay with --url wss://relay1.add.org/ws, it publishes that exact URL to the DHT (via bootstrap)
2. Client lookup - Client queries bootstrap → learns wss://relay-asia.gnoppix.org/ws
3. Client connects - Client connects to wss://relay-asia.gnoppix.org/ws (port 443, standard HTTPS)

The --url parameter is critical - it tells the network: "This is my public-facing address". The internal port 8765 is now never shown to clients.

---

## Desktop UI App

Add includes an Electron desktop client with a Signal-inspired interface.

### Features

- **Split-pane layout**: 30% sidebar (conversations), 70% chat pane
- Real-time message list with auto-scroll
- Message status indicators (sending, sent, delivered, read)
- Unread message badges
- TypeScript + Zustand state management

### Prerequisites

- Node.js 18+
- npm or yarn

### Development

```bash
cd desktop-ui
npm install
npm run dev           # Starts Vite dev server + Electron
npm run dev:react     # React only (http://localhost:5173)
npm run dev:electron  # Electron only (connects to Vite)
```

### Build for Production

```bash
cd desktop-ui
npm run build         # React + Electron packages
npm run build:react   # React only
npm run build:electron # Electron package via electron-builder
```

### Web Browser Testing

To test the React UI in a browser without Electron:

```bash
cd desktop-ui
npm run dev:react
# Open http://localhost:5173 in any browser
```

The UI runs standalone for development/testing. Production builds load from the Electron app.

---

## What is the Reflector Bot?

The Reflector Bot (`add-reflector`) is an automated Echo Bot for testing latency and verifying the protocol works correctly. It runs as a headless client and reflects any message it receives back to the sender.

### Features

- **Echo functionality**: Sends received message back with `🤖 [Reflector Echo]:` prefix
- **TTL inheritance**: Echo messages inherit the sender's TTL setting
- **E2E read receipt**: Sends `p2p-receipt` on receipt (Double Check ✅✅)
- **Loop prevention**: Drops messages from known bots to prevent infinite loops
- **Zero-footprint storage**: In-memory SQLite, auto-cleanup after TTL expires

### Usage

```bash
# Build bot
cargo build -p add-bot

# Run continuously
./target/debug/add-reflector

# Single cycle (for testing)
./target/debug/add-reflector --once
```

Send any message to `NN-B0T-REFL` (or use the "🤖 Reflector Bot" contact in the desktop UI) to test end-to-end delivery.

---

## Documentation

- **[README.md](README.md)** — Project overview and quick start
- **[DEVELOPER.md](DEVELOPER.md)** — Architecture, module contracts, ACS2.6 compliance
- **[WORKLIST.md](WORKLIST.md)** — Current tasks and progress
- **[CHANGELOG.md](CHANGELOG.md)** — Version history

---

## License

Business Source License (BSL / BUSL).
You can use the code for free if your company or organisation doesn't have more than 2 people.
