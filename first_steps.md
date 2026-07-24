# First Steps: TPM Setup for Add Messenger on Gnoppix

## 1. Install Required Packages

```bash
sudo apt-get update
sudo apt-get install -y libtss2-dev libssl-dev tpm2-abrmd libtss2-tcti-tabrmd0
```

## 2. Start TPM Resource Manager (tpm2-abrmd)

```bash
sudo systemctl enable --now tpm2-abrmd
sudo systemctl status tpm2-abrmd
```

Verify it's running:
```
● tpm2-abrmd.service - TPM2 Access Broker and Resource Management Daemon
   Active: active (running)
```

## 3. Add User to `tss` Group

```bash
sudo usermod -a -G tss $USER
```

**Log out and back in** (or run `newgrp tss` in current shell) for group change to take effect.

Verify:
```bash
id $USER | grep tss
```

## 4. Verify TPM Access

```bash
# Should show tpm0 and tpmrm0
ls -la /dev/tpm*

# Test via tabrmd (requires tpm2-tools)
tpm2_getcap --tcti=tabrmd properties-fixed
```

## 5. Fix Rust Code: Use tabrmd TCTI Instead of Direct Device

Edit `/home/amu/Gnoppix/messenger/Add/crypto/src/tpm_vault.rs`, line ~361:

**Before:**
```rust
let tcti = TctiNameConf::Device(Default::default());
```

**After:**
```rust
use std::str::FromStr;
let tcti = TctiNameConf::from_str("tabrmd:bus_name=com.intel.tss2.Tabrmd").unwrap();
```

Add `use std::str::FromStr;` at the top of the `tpm` module (line ~330).

Or use environment variable (alternative):
```bash
export TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
```

## 6. Fix CLI Unlock: Support Both TPM and Passphrase Modes

Edit `/home/amu/Gnoppix/messenger/Add/client/src/main.rs`, around line 5752-5767:

**Before:**
```rust
#[cfg(feature = "tpm")]
if let Some(ref pin) = pin {
    vault.unseal_from_tpm(pin.as_bytes()).map_err(|e| e.into())
} else {
    Err(add_crypto::CryptoError::Io("Either --pin or --password required for unlock".to_string()).into())
}
#[cfg(not(feature = "tpm"))]
if let Some(ref pw) = password {
    add_crypto::unseal_with_passphrase(&vault, pw.as_bytes())
        .map_err(|e| e.into())
} else {
    Err(add_crypto::CryptoError::Io("Either --pin or --password required for unlock".to_string()).into())
}
```

**After:**
```rust
#[cfg(feature = "tpm")]
{
    if let Some(ref pin) = pin {
        vault.unseal_from_tpm(pin.as_bytes()).map_err(|e| e.into())
    } else if let Some(ref pw) = password {
        add_crypto::unseal_with_passphrase(&vault, pw.as_bytes())
            .map_err(|e| e.into())
    } else {
        Err(add_crypto::CryptoError::Io("Either --pin or --password required for unlock".to_string()).into())
    }
}
#[cfg(not(feature = "tpm"))]
if let Some(ref pw) = password {
    add_crypto::unseal_with_passphrase(&vault, pw.as_bytes())
        .map_err(|e| e.into())
} else {
    Err(add_crypto::CryptoError::Io("Either --pin or --password required for unlock".to_string()).into())
}
```

## 7. Rebuild with TPM Feature

```bash
cd /home/amu/Gnoppix/messenger/Add
cargo build --package add-client --release --features tpm
mkdir -p target/bundle
cp target/release/add target/bundle/add
chmod +x target/bundle/add
```

## 8. Rebuild Desktop App

```bash
cd /home/amu/Gnoppix/messenger/Add/desktop-ui
npm run build:react && npm run fix:index && ./node_modules/.bin/electron-builder --config electron-builder.js --linux --publish=never
```

## 9. Test Identity Creation

```bash
# Clean slate
rm -rf ~/.add

# ============================================
# TPM MODE (hardware-backed, requires TPM chip + tss group)
# ============================================
sg tss -c "dist-electron/linux-unpacked/resources/add init --pin 123456"

# OR without sg if you logged out/in after adding to tss group:
# dist-electron/linux-unpacked/resources/add init --pin 123456

# ============================================
# PASSPHRASE MODE (software, no TPM needed)
# ============================================
dist-electron/linux-unpacked/resources/add init --password "Ab1!Cd2#Ef3@Gh4$"
```

**Requirements:**
- PIN: exactly 6 digits (e.g., `123456`)
- Passphrase: 16+ chars with upper, lower, digit, special (e.g., `Ab1!Cd2#Ef3@Gh4$`)

Expected output:
```
Identity created successfully!
  Fingerprint: ...
  Null ID:     NN-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx

Vault created at ~/.add/vault.json
```

Verify vault type:
```bash
cat ~/.add/vault.json
# TPM mode:   "kind": { "t": "Tpm", "d": { "sealed_b64": "..." } }
# Passphrase: "kind": { "t": "Passphrase", "d": { "wrapped_b64": "..." } }
```

## 10. Test Unlock

```bash
# TPM mode (requires tss group)
sg tss -c "dist-electron/linux-unpacked/resources/add unlock --pin 123456"

# Passphrase mode
dist-electron/linux-unpacked/resources/add unlock --password "Ab1!Cd2#Ef3@Gh4$"
```

Expected: `Vault unlocked successfully.`

## 11. Run Desktop App

```bash
# Dev mode (won't have TPM - no preload)
npm run dev:electron

# Packaged app (has TPM via preload + bundled binary)
./dist-electron/linux-unpacked/add-desktop
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `Permission denied /dev/tpm0` | User not in `tss` group or tpm2-abrmd not running |
| `No standard TCTI could be loaded` | Install `libtss2-tcti-tabrmd0`, restart tpm2-abrmd |
| `ESYS init: Tss2Error(...)` | Use `Tabrmd` TCTI instead of `Device` in Rust code |
| "Add API not available" in browser | Dev mode lacks preload; use packaged app |
| Vault shows `Passphrase` not `Tpm` | Binary built without `--features tpm` |

## Notes

- The desktop app **must** run as packaged (`dist-electron/linux-unpacked/add-desktop`) for TPM to work — dev mode (`npm run dev:electron`) loads from Vite without Electron's preload script, so `window.addAPI` is undefined.
- TPM sealing requires the SRK (Storage Root Key) at persistent handle `0x81000001`. If not present, run `tpm2_createprimary` + `tpm2_evictcontrol` or use `systemd-tpm2-setup.service`.
- Self-destruct after 10 failed PIN attempts is enforced by the TPM hardware (authValue = SHA-256("add-pin-v1" + PIN)).