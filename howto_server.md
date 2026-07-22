# Running Your Own Bootstrap & Relay Servers

This guide documents the complete setup for deploying Add bootstrap and relay servers with nginx TLS termination (v0.3.26+ architecture).

---

## Architecture Overview

```
Public Internet (Port 443)
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│                    nginx (stream module)                     │
│  listen 443; ssl_preread on;                                 │
│                                                              │
│  map $ssl_preread_server_name $backend_route {               │
│    bootstrap-<region>.gnoppix.org bootstrap_backend;         │
│    relay-<region>.gnoppix.org     relay_backend;             │
│    default                      web_backend;                 │
│  }                                                           │
│                                                              │
│  upstream bootstrap_backend { server 127.0.0.1:9001; }       │
│  upstream relay_backend     { server 127.0.0.1:8765; }       │
│  upstream web_backend       { server 127.0.0.1:8443; }       │
└──────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   127.0.0.1:9001      127.0.0.1:8765      127.0.0.1:8443
   add-bootstrap       add-relay            nginx http
   (TLS)               (TLS)                (web vhosts)
```

**Ports:**
- **443** — Public TLS (nginx stream, SNI routing)
- **9001** — Bootstrap (TLS, localhost only)
- **8765** — Relay (TLS, localhost only)
- **8443** — Web vhosts (internal, localhost only)

---

## Prerequisites

### System Requirements
- Linux (Debian/Ubuntu tested)
- Root access
- Public IPv4 address with DNS control
- Let's Encrypt certificates (or your own CA)

### DNS Records Required
```
bootstrap-<region>.gnoppix.org  A  <your-ipv4>
relay-<region>.gnoppix.org      A  <your-ipv4>
```
Replace `<region>` with your region code (us, eu, asia, etc.)

### Let's Encrypt Certificates
```bash
# Bootstrap cert
certbot certonly --standalone -d bootstrap-<region>.gnoppix.org

# Relay cert
certbot certonly --standalone -d relay-<region>.gnoppix.org
```
Certificates will be at:
```
/etc/letsencrypt/live/bootstrap-<region>.gnoppix.org/fullchain.pem
/etc/letsencrypt/live/bootstrap-<region>.gnoppix.org/privkey.pem
/etc/letsencrypt/live/relay-<region>.gnoppix.org/fullchain.pem
/etc/letsencrypt/live/relay-<region>.gnoppix.org/privkey.pem
```

---

## 1. Build Binaries

```bash
git clone https://github.com/gnoppix/Add.git
cd Add

# Build release binaries
cargo build --release -p add-bootstrap -p add-relay

# Binaries at:
# target/release/add-bootstrap
# target/release/add-relay
```

---

## 2. Install nginx with Stream Module

### Debian/Ubuntu
```bash
apt update
apt install nginx libnginx-mod-stream
```

### Verify Stream Module
```bash
nginx -V 2>&1 | grep -o with-stream
# Should output: with-stream
```

---

## 3. nginx Configuration

### Main Config: `/etc/nginx/nginx.conf`
```nginx
user www-data;
worker_processes auto;
worker_cpu_affinity auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
load_module /usr/lib/nginx/modules/ngx_stream_module.so;

events {
    worker_connections 768;
}

http {
    limit_req_zone $binary_remote_addr zone=ws:10m rate=5r/s;
    
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

stream {
    map $ssl_preread_server_name $backend_route {
        bootstrap-<region>.gnoppix.org bootstrap_backend;
        relay-<region>.gnoppix.org     relay_backend;
        default                      web_backend;
    }

    upstream bootstrap_backend { server 127.0.0.1:9001; }
    upstream relay_backend     { server 127.0.0.1:8765; }
    upstream web_backend       { server 127.0.0.1:8443; }

    server {
        listen 443;
        listen [::]:443;          # Remove if no IPv6
        ssl_preread on;
        proxy_pass $backend_route;
        proxy_timeout 3600s;
        proxy_buffer_size 4k;
    }
}
```

### Move Web Vhosts Off Port 443
Edit all vhosts in `/etc/nginx/sites-enabled/`:
```nginx
# Change from:
listen 443 ssl;
listen [::]:443 ssl;

# To:
listen 8443 ssl;
# Remove [::]:8443 if no IPv6
```

---

## 4. Deploy Binaries

### Directory Structure
```bash
mkdir -p /root/add
cp target/release/add-bootstrap /root/add/
cp target/release/add-relay /root/add/
chmod +x /root/add/add-bootstrap /root/add/add-relay
```

### Data Directory
```bash
mkdir -p /root/.add
chmod 700 /root/.add
```

---

## 5. Run Bootstrap Server

### Command
```bash
/root/add/add-bootstrap \
  --host 127.0.0.1 \
  --port 9001 \
  --advertised-url wss://bootstrap-<region>.gnoppix.org/ws \
  --tls-cert /etc/letsencrypt/live/bootstrap-<region>.gnoppix.org/fullchain.pem \
  --tls-key /etc/letsencrypt/live/bootstrap-<region>.gnoppix.org/privkey.pem
```

### What It Does
- Listens on `127.0.0.1:9001` with TLS
- Advertises public URL `wss://bootstrap-<region>.gnoppix.org/ws` in DHT
- Stores DHT data in `/root/.add/bootstrap_dht.db`
- Generates persistent Kyber keypair for bootstrap identity

### Systemd Service: `/etc/systemd/system/add-bootstrap.service`
```ini
[Unit]
Description=Add Messenger Bootstrap Server (<region>)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/root/add/add-bootstrap \
  --host 127.0.0.1 \
  --port 9001 \
  --advertised-url wss://bootstrap-<region>.gnoppix.org/ws \
  --tls-cert /etc/letsencrypt/live/bootstrap-<region>.gnoppix.org/fullchain.pem \
  --tls-key /etc/letsencrypt/live/bootstrap-<region>.gnoppix.org/privkey.pem
Restart=always
RestartSec=5
User=root
WorkingDirectory=/root/add
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

## 6. Run Relay Server

### Command
```bash
/root/add/add-relay \
  --host 127.0.0.1 \
  --port 8765 \
  --url wss://relay-<region>.gnoppix.org/ws \
  --tls-cert /etc/letsencrypt/live/relay-<region>.gnoppix.org/fullchain.pem \
  --tls-key /etc/letsencrypt/live/relay-<region>.gnoppix.org/privkey.pem \
  --bootstrap wss://bootstrap-<region>.gnoppix.org/ws \
  --bootstrap wss://bootstrap-<other-region1>.gnoppix.org/ws \
  --bootstrap wss://bootstrap-<other-region2>.gnoppix.org/ws
```

### What It Does
- Listens on `127.0.0.1:8765` with TLS
- Store-and-forward mailbox for offline clients
- Proxies DHT lookups through bootstrap (metadata hardening)
- Persistent mailbox in `/root/.add/mailbox.db` (or GPG home)

### Systemd Service: `/etc/systemd/system/add-relay.service`
```ini
[Unit]
Description=Add Messenger Relay Server (<region>)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/root/add/add-relay \
  --host 127.0.0.1 \
  --port 8765 \
  --url wss://relay-<region>.gnoppix.org/ws \
  --tls-cert /etc/letsencrypt/live/relay-<region>.gnoppix.org/fullchain.pem \
  --tls-key /etc/letsencrypt/live/relay-<region>.gnoppix.org/privkey.pem \
  --bootstrap wss://bootstrap-us.gnoppix.org/ws \
  --bootstrap wss://bootstrap-eu.gnoppix.org/ws \
  --bootstrap wss://bootstrap-asia.gnoppix.org/ws
Restart=always
RestartSec=5
User=root
WorkingDirectory=/root/add
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

## 7. Enable & Start Services

```bash
# Reload systemd
systemctl daemon-reload

# Enable and start
systemctl enable --now add-bootstrap
systemctl enable --now add-relay
systemctl enable --now nginx

# Check status
systemctl status add-bootstrap
systemctl status add-relay
systemctl status nginx
```

---

## 8. Verify Deployment

### Check Listening Ports
```bash
ss -tlnp | grep -E "443|9001|8765|8443"
```
Expected:
```
LISTEN 0 0.0.0.0:443      (nginx stream)
LISTEN 0 127.0.0.1:9001  (add-bootstrap)
LISTEN 0 127.0.0.1:8765  (add-relay)
LISTEN 0 127.0.0.1:8443  (nginx http)
```

### Test TLS + SNI Routing
```bash
# Bootstrap
openssl s_client -connect 127.0.0.1:443 -servername bootstrap-<region>.gnoppix.org </dev/null

# Relay
openssl s_client -connect 127.0.0.1:443 -servername relay-<region>.gnoppix.org </dev/null

# Web fallback
openssl s_client -connect 127.0.0.1:443 -servername gnoppix.org </dev/null
```
All should show `Verification: OK` with correct certificate CN.

### Test Client Connectivity
```bash
# From client machine
add id
add publish-cert
add send <contact> "test"
```

---

## 9. Bootstrap Certificate Sync (Multi-Region)

Bootstrap nodes **do not federate** automatically. You must manually sync certs:

```bash
# On source bootstrap (e.g., EU)
sqlite3 /root/.add/bootstrap_dht.db "SELECT key, value FROM kv_store WHERE key LIKE 'cert:%';"

# On target bootstrap (e.g., US, Asia) - for each key:
sqlite3 /root/.add/bootstrap_dht.db \
  "INSERT OR REPLACE INTO kv_store (key, value, salt, seq, publisher_fp, stored_at, expires_at, sig) \
   VALUES ('<key>', '<value>', '', 0, '', strftime('%s','now'), strftime('%s','now','+1 year'), '');"
```

---

## 10. Maintenance

### Logs
```bash
journalctl -u add-bootstrap -f
journalctl -u add-relay -f
tail -f /var/log/nginx/error.log
```

### Certificate Renewal
```bash
# After certbot renewal, reload nginx and restart binaries
systemctl reload nginx
systemctl restart add-bootstrap add-relay
```

### Database Backup
```bash
# Bootstrap DHT
cp /root/.add/bootstrap_dht.db /backup/bootstrap_dht.db.$(date +%F)

# Relay mailbox
cp /root/.add/mailbox.db /backup/mailbox.db.$(date +%F)
```

### Update Binaries
```bash
cd /path/to/Add
git pull
cargo build --release -p add-bootstrap -p add-relay
cp target/release/add-bootstrap /root/add/
cp target/release/add-relay /root/add/
systemctl restart add-bootstrap add-relay
```

---

## 11. Security Checklist

- [ ] All binaries run as root but bind only to 127.0.0.1
- [ ] Port 443 only exposed via nginx stream (no direct binary exposure)
- [ ] Let's Encrypt certs auto-renew (certbot timer active)
- [ ] GPG home directory permissions: `chmod 700 /root/.add/gnupg`
- [ ] `db_key.json` (passphrase-derived) is `600` permissions
- [ ] No IPv6 listeners if server lacks IPv6 (`listen [::]:` removed)
- [ ] Firewall: only port 443/80 open publicly

---

## 12. Quick Reference

| Component | Command | Port | TLS |
|-----------|---------|------|-----|
| nginx (stream) | `systemctl restart nginx` | 443 | Yes (SNI) |
| bootstrap | `add-bootstrap --port 9001` | 9001 | Yes |
| relay | `add-relay --port 8765` | 8765 | Yes |
| web vhosts | nginx http | 8443 | Yes (internal) |

**Public URLs:**
- Bootstrap: `wss://bootstrap-<region>.gnoppix.org/ws`
- Relay: `wss://relay-<region>.gnoppix.org/ws`

**Internal URLs (nginx → backend):**
- Bootstrap: `127.0.0.1:9001`
- Relay: `127.0.0.1:8765`
- Web: `127.0.0.1:8443`
