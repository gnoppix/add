# Add Reflector Bot

Automated Echo Bot for P2P/Relay protocol testing and latency measurement.

## Overview

The Reflector Bot (`add-reflector`) is a standalone headless client that receives messages and echoes them back to the sender. It's useful for:

- **Latency testing** — Measure end-to-end delivery time
- **Protocol verification** — Confirm P2P and relay paths work correctly
- **E2E confirmation** — Verify Double Check (✔️✔️) read receipts function

## Features

| Feature | Description |
|---------|-------------|
| Echo functionality | Reflects messages with `🤖 [Reflector Echo]:` prefix |
| TTL inheritance | Echo messages use sender's TTL setting |
| Read receipts | Sends `p2p-receipt` on receipt (Double Check ✅✅) |
| Loop prevention | Drops own messages and known bot prefixes |
| Zero-footprint storage | In-memory SQLite with auto-cleanup |

## Quick Start

```bash
# Build
cargo build -p add-bot

# Run continuously
./target/debug/add-reflector

# Single cycle (for testing)
./target/debug/add-reflector --once
```

## Configuration

Configuration file at `~/.add/bot/bot.toml`:

```toml
[identity]
null_id = "NN-B0T-REFL"

[reflector]
prefix = "🤖 [Reflector Echo]:"
default_ttl = "2h"
known_bot_prefixes = ["NN-B0T-REFL", "NN-TEST-"]

[network]
polling_interval = 30
relay_urls = ["wss://relay-us.gnoppix.org/ws"]
```

## CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Config file path | `~/.add/bot/bot.toml` |
| `--prefix` | Override echo prefix | (from config) |
| `--ttl` | Override default TTL | (from config) |
| `--once` | Single cleanup cycle, then exit | false |
| `--log-level` | Log verbosity | `info` |

## Event Flow

```
OnMessageReceived
    → SendReadReceipt (Double Check ✔️✔️)
    → CheckLoopPrevention (drop if sender is bot)
    → ConstructEchoPayload (prefix + original + TTL inheritance)
    → RouteOutbound (P2P direct or relay fallback)
    → DeleteAfterEcho (cleanup immediately)
```

## Integration

- **CLI client**: `NN-B0T-REFL` auto-added during `add init`
- **Desktop UI**: "🤖 Reflector Bot" appears in contact list automatically

## Development

The bot crate is part of the Add workspace. Build with:

```bash
cd /home/amu/gnoppix/messages/Add
cargo build -p add-bot
```

## See Also

- [README.md](../README.md) — Project overview
- [DEVELOPER.md](../DEVELOPER.md) — Architecture and module contracts
- [FAQ.md](../FAQ.md) — Reflector Bot FAQ section