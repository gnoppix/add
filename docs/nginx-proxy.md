# Nginx TLS Proxy Deployment

Add bootstrap and relay can run behind nginx on port 443 with TLS termination.
The daemon binds to localhost (plaintext ws://) and nginx forwards decrypted WebSocket
traffic to it.

## Architecture

```
Client (wss://bootstrap.example.com:443)
    │
    ▼
nginx (TLS termination, certbot/Let's Encrypt)
    │
    ▼
proxy_pass http://127.0.0.1:9001  (ws:// plaintext, localhost only)
    │
    ▼
add-bootstrap (listening on 127.0.0.1:9001)
```

## nginx.conf

```nginx
# Rate limiting zone for WebSocket connections
limit_req_zone $binary_remote_addr zone=ws:10m rate=10r/s;

# Upstream for the Add bootstrap daemon
upstream eva_bootstrap {
    server 127.0.0.1:9001;
    keepalive 32;
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name bootstrap.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name bootstrap.example.com;

    # TLS certificates (certbot or manual)
    ssl_certificate     /etc/letsencrypt/live/bootstrap.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/bootstrap.example.com/privkey.pem;

    # Modern TLS 1.3 only
    ssl_protocols TLSv1.3;
    ssl_ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers on;

    # Fallback page: serve a static site for non-WebSocket requests
    # This defeats active probing — the server looks like a normal website
    root /var/www/bootstrap-fallback;
    index index.html;

    # WebSocket endpoint → Add daemon
    location /ws {
        limit_req zone=ws burst=20 nodelay;

        proxy_pass http://eva_bootstrap;
        proxy_http_version 1.1;

        # WebSocket upgrade headers
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;

        # Forward client IP for rate limiting
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout settings (keep WebSocket alive)
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Buffer settings for streaming P2P messages
        proxy_buffering off;
    }

    # Fallback: serve static content for everything else
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

## Fallback Page

Create a benign static site at `/var/www/bootstrap-fallback/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bootstrap Documentation</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 4em auto; padding: 0 1em; }
        code { background: #f4f4f4; padding: 0.2em 0.4em; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Add Bootstrap Node</h1>
    <p>This is a post-quantum P2P network bootstrap node. It does not serve a web interface.</p>
    <p>API documentation: <a href="https://docs.gnoppix.com">https://docs.gnoppix.com</a></p>
</body>
</html>
```

## Bootstrap Server Configuration

Run the bootstrap daemon bound to localhost with `--advertised-url` pointing to nginx:

```bash
./target/release/add-bootstrap \
    --host 127.0.0.1 \
    --port 9001 \
    --advertised-url wss://bootstrap.example.com/ws \
    --db ~/.add/bootstrap_dht.db
```

The `--advertised-url` tells DHT clients to connect via `wss://bootstrap.example.com/ws`
(through nginx) instead of the internal `127.0.0.1:9001`.

## Client Configuration

Clients connect through the nginx proxy automatically when using the public URL:

```bash
# The client uses wss:// automatically when the URL starts with https://
eva init
eva id
```

## Security Considerations

1. **SNI**: The TLS SNI field shows `bootstrap.example.com` (the nginx domain) — not
   a suspicious P2P-looking hostname. This is innocuous and blends with normal HTTPS.

2. **Certificate pinning**: Clients verify the nginx server certificate via WebPKI
   (standard root CA store). The TOFU pin cache stores the nginx domain's cert
   fingerprint. Operators should use a long-lived certificate.

3. **Rate limiting**: nginx `limit_req_zone` prevents DHT scanning abuse. Adjust
   `rate=10r/s` based on expected legitimate traffic.

4. **Fallback page**: Any non-WebSocket request to `/` receives a normal HTML page.
   Active probes hitting the server see a documentation site, not a WebSocket timeout.

5. **No TLS in the daemon**: The bootstrap binary runs in plaintext mode on localhost.
   This simplifies the attack surface — no TLS parsing in the unprivileged process.
