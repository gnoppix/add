# Listener Behind NAT — Permanent Direct P2P via :443 Reverse Proxy

## Problem

The canonical Add topology is `public-peer → NATted-peer`. When the listener
(`add listen`) sits behind a NAT with **no UPnP/IGD and no manual port-forward**,
inbound connections to the listener's public IP:port are dropped by the NAT, so
direct P2P times out and the message falls back to the relay.

This is unfixable from the client alone when:
- the NATted peer must **not** initiate outbound to the public peer (no hole
  punch from listener → sender), and
- the router does not serve UPnP IGD and no port-forward is configured.

The relay *works* in this case, but if you want true direct P2P, you need inbound
to reach the listener. The only way without touching the router is to **front the
listener with a reverse proxy on port 443** that the listener reaches via its own
outbound connection.

## Why this is permanent and needs no router changes

```
debian (public, no NAT)                amu (behind NAT)
       │                                     │
       │  wss://amu.example.com:443          │  (listener binds 0.0.0.0:42887,
       │  (TLS, public, reachable)           │   reaches nginx via OUTBOUND)
       ▼                                     ▲
   nginx on amu :443  ──proxy_pass──►  ws://127.0.0.1:42887 (add listen)
```

- `debian` dials `wss://amu.example.com:443` — a normal public HTTPS endpoint.
- nginx terminates TLS and forwards the WebSocket to the local `add listen`
  process on `amu:42887`.
- `amu`'s NAT never has to accept *unsolicited* inbound: nginx is reachable on
  `:443` from the internet (open inbound on :443 is standard and allowed), and the
  proxy_pass to localhost is internal — no NAT traversal required.
- `amu` never dials `debian`; it only listens locally and lets nginx receive.
- End-to-end message encryption (Double Ratchet + ML-KEM-1024) is unchanged — nginx
  sees only ciphertext.

This satisfies all constraints: no UPnP, no port-forward, listener stays the
dialed party, sender stays the dialer.

## Setup

### 1. Run the listener bound to localhost

```bash
./target/release/add listen \
    --host 0.0.0.0 \
    --port 42887 \
    --advertised-url wss://amu.example.com/ws
```

`--advertised-url` tells DHT/presence to publish `wss://amu.example.com/ws` as the
incoming address, so `debian` connects through nginx instead of the unreachable
NAT IP.

### 2. nginx reverse proxy (port 443)

```nginx
limit_req_zone $binary_remote_addr zone=ws:10m rate=20r/s;

upstream add_listener {
    server 127.0.0.1:42887;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name amu.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name amu.example.com;

    ssl_certificate     /etc/letsencrypt/live/amu.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/amu.example.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers on;

    root /var/www/add-listener-fallback;
    index index.html;

    location /ws {
        limit_req zone=ws burst=40 nodelay;
        proxy_pass http://add_listener;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Replace `amu.example.com` with the listener's real public DNS name (an A/AAAA
record pointing at `amu`'s public IP). Obtain the cert with
`certbot --nginx -d amu.example.com`.

### 3. Benign fallback page

Create `/var/www/add-listener-fallback/index.html` (any harmless static page) so
active probes see a normal website, not a WebSocket timeout. This makes the
endpoint blend with ordinary HTTPS (see "Why port 443 makes Add hard to detect"
in nginx-proxy.md).

### 4. Verify

On `debian` (or any peer):

```bash
./add send NN-TuXM-Nb6u "direct via proxy"
```

The log should show `Establishing P2P connection...` followed by successful
delivery **without** a `using relay delivery` line. The listener log on `amu`
shows the inbound connection arriving through nginx.

## Fallback

If nginx/`:443` is unavailable, the relay remains the correct delivery path — it
already works for `public → NATted` without any of the above. The proxy only
upgrades the path from relay to direct P2P.
