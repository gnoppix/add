# Add


**Post Quantum Encryption, decentralized modern free opensource messaging that needs no phone, no email, and no personal information, no company in between.**

Think of it like sending secret notes directly to your friend's house — but the mailman, the post office, and even the government can't read them. Add is a messenger that connects you directly to the people you talk to. No company sits in the middle seeing your messages.

Every message is protected by the strongest encryption available today (ML-KEM-1024, the US government's post-quantum standard). Even if someone records everything now and builds a supercomputer in 20 years, they still can't decrypt it.

Sessions persist across restarts — if you receive a message while offline, it gets decrypted and read when you come back.


## Important Disclaimer

- Not Production Ready: This project is currently undergoing active, volatile development.

- Security & Stability: Core components, especially the End-User UI, are being rewritten and iterated upon daily. Do not deploy this software in production, testing environments with real data, or any sensitive/secure environments. Breakages and breaking changes are to be expected.

## How You Can Support Us

- We are working very hard to bring add to a stable, production-ready state. If you would like to help accelerate our development, here is how you can support us right now:

- Contribute Code: Check out our open issues or submit pull requests for bugs you encounter.

- UI/UX Feedback: Since the End-User UI is under heavy construction, your feedback on layout, usability, and workflows is incredibly valuable.

- Star the Repo: If you believe in the vision of add, drop us a star on GitHub to help increase visibility!

- Spread the Word: Share the project with other developers who might be interested in contributing.

### Thank you for your patience and support as we build the foundation of add!


---

## How it works (the short version)

1. You run `add init` — it creates a unique "key" (like a lock with two halves).
2. The public half becomes your **Null ID** — something like `NN-XXXX-XXXX`. Share this with friends so they can find you.
3. When you send a message, it gets locked with your friend's key and travels directly to them.
4. If they're offline, the message waits in a locked mailbox (the DHT) until they come back online.

It's like BitTorrent, but for private messaging.

---

## Quick start

Add has three binaries. Each is run by a different role:

|| Binary | Run by | What it does |
||---|---|---|
|| `add` | **You** (the user) | Your personal messenger client. You send, read, and receive messages. |
|| `add-relay` | **A relay operator** | A store-and-forward server. Holds encrypted messages until the recipient comes online. |
|| `add-bootstrap` | **A seed server operator** | The DHT seed node. Clients look it up to find peers. Think of it as the "phone book". |
|| `add-reflector` | **Testing / diagnostics** | Automated Echo Bot that reflects messages back. Useful for latency testing and protocol verification. |

### 1. Build everything


```bash
sudo apt install cargo rustc
cd add 
make all
```

This produces three binaries in `target/release/`:
- `add`       — the client
- `add-relay` — the relay server
- `add-bootstrap` — the DHT seed server

### 2. A user creates their identity

```bash
./target/release/add init
```

This creates `~/.add/` with your ML-KEM keypair and prints your Null ID:

```
Null ID: NN-A1B2-C3D4
Fingerprint: ABCD1234...
```

Share your Null ID with friends so they can send you messages. Share your **fingerprint** with contacts so they can verify your identity.

### 3. Show your ID anytime

```bash
./target/release/add id
```

### 4. Add a contact

```bash
./target/release/add add-contact NN-E5F6-G7H8 67902E417B528A287CE75D893EC503E34DEC46E0
```

The `add-contact` command takes the Null ID and fingerprint as **positional arguments** (not flags). The fingerprint is the 40-hex-char string printed by `add id` / `add init`.

### 5. Add an alias (optional, for convenience)

```bash
./target/release/add alias Bob-office NN-E5F6-G7H8
```

Aliases map a short human-readable name to a Null ID. You can then use the alias everywhere a Null ID is expected.

### 7. Send a message

```bash
# Using the Null ID directly (always works)
./target/release/add send NN-E5F6-G7H8 "Hello, Bob!"

# Using the alias (easier to remember)
./target/release/add send Bob-office "Hello, Bob!"

# With auto-destruct timer (message self-destructs after specified time)
./target/release/add send NN-E5F6-G7H8 "This will disappear in 24h" --ttl 24h
./target/release/add send Bob-office "Secret message" --ttl 7d
```

TTL options: `2h`, `12h`, `24h`, `48h`, `5d`, `7d`, `14d`

### 8. Read your messages

```bash
./target/release/add read
```

### 9. Delete a message

After reading, messages are shown with position numbers. Delete a message by position (1 = newest):

```bash
./target/release/add delete 1
```

This removes the message from your local store.

### 10. Register identity with DHT

If your identity was created while the bootstrap was unreachable, register it explicitly:

```bash
./target/release/add register
```

This sends your Null ID and fingerprint to the bootstrap DHT so others can find you.

### 11. Listen for incoming P2P connections

```bash
./target/release/add listen
```

By default the listener advertises a **publicly-reachable address** so a peer on
the internet can connect to your LAN host (BitTorrent-style NAT traversal):

1. **UPnP/IGD** — if your router supports it, Add asks it to map an
   external port → your listener's internal port, then advertises the
   router's public `ws://IP:port`.
2. **STUN** — if UPnP is unavailable, Add queries a STUN server to
   learn the NAT's public `ws://IP:port` and advertises that.
3. **Raw LAN** — if both fail (e.g. symmetric NAT), it falls back to the
   LAN bind address (`ws://192.168.x.x:PORT`), which is *not* reachable
   from outside your network.

Override or disable:

```bash
# Advertise a fixed public URL (reverse-proxy / relay-fronted wss://).
# Peers connect to this endpoint; nginx (or any proxy) forwards to the host.
./target/release/add listen --advertised-url wss://your.domain/ws

# Skip NAT traversal entirely; advertise the raw LAN address only.
./target/release/add listen --no-nat
```

The advertised address is published as the listener's `addr:<null_id>` record
in the DHT, so peers discover it automatically when you `add send` to them.

---

## Running a server

### Relay server (anyone can run one)

```bash
./target/release/add-relay --host 0.0.0.0 --port 8765
```

Clients connect to this relay to store and fetch messages when the other party is offline.

### Bootstrap DHT seed (usually only a few trusted operators)

```bash
./target/release/add-bootstrap --host 0.0.0.0 --port 9001
```

Clients use this to discover peers and find relay servers. The default `ADD_DHT_BOOTSTRAP` env var points to built-in seeds — you only need to run your own if you want to operate independent infrastructure.

### Behind nginx (TLS on :443)

For production deployments, run the bootstrap behind nginx to get TLS 1.3 on port 443:

```bash
# Bootstrap binds to localhost only — nginx terminates TLS and forwards
./target/release/add-bootstrap \
    --host 127.0.0.1 --port 9001 \
    --advertised-url wss://bootstrap.example.com/ws
```

The bootstrap will automatically use stable IDs (auto-generated Kyber-1024 keypair if no GPG key exists) and operate in "proxy mode" (no TLS warning when `--host` is `127.0.0.1`).

For direct TLS mode (when NOT behind nginx), provide certificates:

```bash
./target/release/add-bootstrap \
    --host 0.0.0.0 --port 443 \
    --tls-cert /etc/letsencrypt/live/bootstrap.example.com/fullchain.pem \
    --tls-key /etc/letsencrypt/live/bootstrap.example.com/privkey.pem
```

See [docs/nginx-proxy.md](docs/nginx-proxy.md) for the full nginx config with WebSocket upgrade,
fallback page, and rate limiting.

---

## Three users example

TODO: Add example with 3 users, relays, and bootstrap coordination

---

## Desktop UI

Add includes an Electron desktop client with a Signal-inspired interface.

### Features

- Split-pane layout (30% sidebar, 70% chat)
- Real-time message list with auto-scroll
- Message status indicators (sending, sent, delivered, read)
- Unread message badges
- **Clean contact list** — starts empty (only your real contacts; no pre-injected entries)
- **Live online status** — probes 5s after launch, then every 27s; "online" means the contact's listener actually answered a connection, not just a stale presence record
- TypeScript + Zustand state management

### Hard to detect

Both the bootstrap and relay servers listen on the standard **HTTPS port 443** over
`wss://` (TLS WebSocket). On the wire, Add traffic is indistinguishable from normal
encrypted web browsing — same port, same TLS handshake, same encrypted stream. A
network observer can't tell it apart from routine HTTPS, so detection and selective
blocking are extremely difficult (blocking Add would mean blocking all HTTPS). Pair
with Tor to also hide *that* you connect and *to whom*.

### Prerequisites

- Node.js 18+
- npm or yarn

### Build & Run

```bash
cd desktop-ui
npm install
npm run dev           # Development mode (Vite + Electron)
npm run build         # Production build (includes .deb package)
```

See [TRANSLATIONS.md](desktop-ui/TRANSLATIONS.md) to add a new language.

### Install Desktop on Debian/Ubuntu

```bash
sudo dpkg -i desktop-ui/dist-electron/add-desktop_0.2.13_amd64.deb
```

The package name is `add-desktop` and the version increments with each build (the bundled `add` CLI is embedded via `electron-builder.json` `extraResources`). Check the actual filename in `desktop-ui/dist-electron/`.

---

## Debian Packages

Pre-built .deb packages for all components:

| Package | Description |
|---------|-------------|
| `add` | CLI client |
| `add-relay` | Relay server |
| `add-bootstrap` | Bootstrap DHT server |
| `add-desktop` | Electron desktop client |
| `add-bot` | Reflector/Echo Bot |

### Build all packages

```bash
make deb-all
```

Or use the build script:

```bash
./scripts/build-deb.sh
```

### Install packages

```bash
sudo dpkg -i target/release/add_*.deb
sudo dpkg -i target/release/add-relay_*.deb
sudo dpkg -i target/release/add-bootstrap_*.deb
sudo dpkg -i target/release/add-bot_*.deb
```

## International Cryptographic Notice

Add was independently developed and is maintained outside of U.S. jurisdiction.

However, because this software utilizes advanced cryptographic primitives (including post-quantum messaging protocols), the import, possession, use, and re-export of this code may be heavily restricted under the laws of your local jurisdiction (including the Wassenaar Arrangement). 

Whether you are downloading this code from a decentralized node or a third-party host, it is your sole responsibility to ensure that possessing or using this software complies with the regulations and policies of your respective country.



