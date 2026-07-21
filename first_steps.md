# First Steps with Add Messenger

Quick start guide for new users: create your identity, add a contact, and exchange test messages.

---

## 1. Initialize Your Identity

Creates your post-quantum identity (GPG + ML-DSA-87 + ML-KEM-1024 keypair).

```bash
add init
```

**What you'll see:**
```
Generating post-quantum keypair (ML-DSA-87, ML-KEM-1024)...
Your Null ID: NN-433d-88c8-38d5-4f66-61f0-a074-c62a-776a
GPG fingerprint: 9DD0503EEC8ECD9A9747ECDAE88A7C95C4EF738B
PQ fingerprint: 1BD93975ED7ADC03B52C363E784BC338F8450C9BBABDC86B5A601FD3C376F39D
```

**Note:** The PQ fingerprint is used for KEM operations and relay messaging. The GPG fingerprint is for the contact list and presence.

---

## 2. Publish Your Certificate

Uploads your public cert (with ML-DSA-87 verifying key + Kyber encapsulation key) to the DHT so others can send you encrypted messages.

```bash
add publish-cert
```

**Interactive:** You'll be prompted for your GPG key passphrase (the one you set during `add init`).

**Headless (systemd/cron):** Set the passphrase via environment variable:
```bash
ADD_DB_PASSPHRASE=yourpassphrase add publish-cert
```

**Expected output:**
```
✓ Certificate published to bootstrap servers.
```

---

## 3. Exchange Identity Information Out-of-Band

To message someone securely, you must exchange your **Null ID** and verify the safety number.

### Show Your Identity Info
```bash
add id
```

**Output:**
```
Null ID: NN-433d-88c8-38d5-4f66-61f0-a074-c62a-776a
Safety number: 9DD0503EEC8ECD9A9747ECDAE88A7C95C4EF738B
PQ fingerprint: 1BD93975ED7ADC03B52C363E784BC338F8450C9BBABDC86B5A601FD3C376F39D
```

Share these with your contact through a verified channel (QR code, voice call, etc.).

---

## 4. Add a Contact

Adds your friend's Null ID to your contact list. Use the **PQ fingerprint** (64-char hex) for KEM operations.

```bash
add add-contact NN-d79c-5c2f-46ff-b7c0-10e2-82a7-d98f-a487
```

(Replace with your friend's actual Null ID)

**Expected output:**
```
✓ Contact added
```

---

## 5. Send a Test Message

Sends an encrypted message to your contact via the relay network (sealed sender).

```bash
add send NN-d79c-5c2f-46ff-b7c0-10e2-82a7-d98f-a487 "Hello from Add!"
```

**Output progression:**
```
Using 3 relay servers:
  [1] wss://relay-eu.gnoppix.org/ws
  [2] wss://relay-asia.gnoppix.org/ws
  [3] wss://relay-us.gnoppix.org/ws
Selected fastest relay: wss://relay-eu.gnoppix.org/ws
Looking up NN-d79c-... ...
DHT lookup failed — using relay delivery...
Message delivered via relay (sealed sender) to NN-d79c-...
```

---

## 5.x Send Message from CLI (Non-Interactive)

For sending in scripts, cron jobs, or other non-interactive contexts where you need to provide all required secrets upfront.

### Required Secrets

| Secret | Purpose | Where it's used |
|--------|---------|-----------------|
| `ADD_DB_PASSPHRASE` | Unlocks your GPG secret key for signing | All signing operations |
| `ADD_RELAY_SHARED_SECRET` | Generates blind routing tag (optional) | Sealed-sender metadata hardening |

### One-Shot Send Command

```bash
# Ensure your contact has published their cert (required for KEM lookup)
ADD_DB_PASSPHRASE=yourenteredpassphrase \
add send NN-d79c-5c2f-46ff-b7c0-10e2-82a7-d98f-a487 "Test message from CLI"
```

**Full non-interactive example (send to friend, read reply):**
```bash
# Send message
export ADD_DB_PASSPHRASE=mysecretpass
add send "NN-d79c-5c2f-46ff-b7c0-10e2-82a7-d98f-a487" "Hey, testing Add messenger!"

# Later, poll for replies
add read
```

### What You'll See When Sending

```
$ ADD_DB_PASSPHRASE=secret add send NN-d79c-5c2f-46ff-b7c0-10e2-82a7-d98f-a487 "Test message"
2026-07-21T01:15:23.192307Z  INFO add: Using discovered bootstrap server: wss://bootstrap-us.gnoppix.org/ws
2026-07-21T01:15:23.192317Z  INFO add: Using 3 relay servers:
...
Selected fastest relay: wss://relay-eu.gnoppix.org/ws
Looking up NN-d79c-... ...
DHT lookup failed — using relay delivery...
2026-07-21T01:15:30.892109Z  INFO add: DBG send blob_has_kc=true sb_len=4115
2026-07-21T01:15:30.892112Z  INFO add: relay-store sent, waiting for response... (relay=wss://relay-eu.gnoppix.org/ws)
2026-07-21T01:16:22.445139Z  INFO add: DBG store resp: {"ok":true,"error":null,"data":null}
Message delivered via relay (sealed sender) to NN-d79c-5c2f-46ff-b7c0-10e2-82a7-d98f-a487
```

If the recipient hasn't published their certificate, you'll see:
```
Error: "cert not found: dht-error"
```
Run `add publish-cert` on the recipient's machine first.

---

## 7. Read Messages

Polls all relays for new messages addressed to you.

```bash
add read
```

**Output:**
```
Checking 3 relay mailbox(s)...
Messages (3):
  [1] [NN-433d-88c8-38d5-4f66-61f0-a074-c62a-776a] [Hello US from local amu - PQ messenger test 2026-07-20]
  [2] [NN-433d-88c8-38d5-4f66-61f0-a074-c62a-776a] [delivery-probe-2]
  [3] [NN-433d-88c8-38d5-4f66-61f0-a074-c62a-776a] [TEST-1784595572]
  Relay purge response: {"ok":true,"error":null,"data":null}
```

Messages are automatically marked delivered and removed from the relay after decryption.

---

## 8. Headless Operation (Optional)

For running `add` in a headless environment (scripts, systemd, etc.):

```bash
export ADD_DB_PASSPHRASE=your_gpg_passphrase

# Can now run commands without interactive prompts:
add publish-cert
add read
add send NN-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx "automated message"
```

Both `publish-cert` and `read` honor this environment variable.

---

## 9. Quick Reference

| Command | Purpose | Required Input |
|---------|---------|----------------|
| `add init` | Create identity | GPG passphrase (set once) |
| `add id` | Show identity info | None |
| `add publish-cert` | Publish cert to DHT | GPG passphrase |
| `add add-contact <null_id>` | Add contact | Contact's Null ID |
| `add send <null_id> <text>` | Send message | Recipient Null ID + message text |
| `add read` | Check messages | Passphrase (or `ADD_DB_PASSPHRASE`) |

---

## 10. Troubleshooting

### "cert not found" error when sending
- Ensure both sender and recipient have run `publish-cert`
- Verify the recipient's Null ID was added correctly (`add contacts`)

### "Connection reset without closing handshake" 
- Transient network issue; retry the command
- Check your internet connectivity

### Messages not decrypting
- Both parties must have each other's Null IDs as contacts
- A fresh `init` may have been run; exchange identities again