# ngx_http_mtproto_module

Nginx module that turns any existing HTTPS server into an MTProto proxy (Telegram). Runs on port 443 alongside regular TLS traffic — MTProto clients are detected transparently, everything else is served by nginx as usual.

## How it works

```
Client ──TLS──▶ nginx:443
                  │
                  ├─ HMAC match → FakeTLS + obfuscated2 → Telegram DC
                  │
                  └─ no match   → regular nginx SSL (website, reverse proxy, etc.)
```

The module intercepts the TLS ClientHello via `MSG_PEEK` **before** OpenSSL processes it. An HMAC-SHA256 check on the client random field determines whether the connection is from a Telegram client or a regular browser. Non-matching connections fall through to nginx with zero overhead — the data stays in the socket buffer untouched.

For MTProto clients the module performs:
1. **FakeTLS handshake** — generates a valid-looking TLS ServerHello with an HMAC-signed random
2. **Obfuscated2 decryption** — derives AES-256-CTR keys from the 64-byte obfuscation header
3. **DC relay** — bidirectional proxying between the client and the target Telegram datacenter, wrapping/unwrapping TLS application data records

Single C file, no external dependencies beyond OpenSSL (already required by nginx).

## Installation

### From .deb package (Debian/Ubuntu)

Download the `.deb` for your distro from [Releases](../../releases):

```bash
sudo dpkg -i libnginx-mod-http-mtproto_*.deb
```

Add to your `nginx.conf` (top level):

```nginx
load_module modules/ngx_http_mtproto_module.so;
```

Then reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Packages are available for Debian 12 (bookworm), Ubuntu 22.04 (jammy), and Ubuntu 24.04 (noble).

## Building

### As a dynamic module

```bash
# Use --with-compat to build against installed nginx
./configure --with-compat \
            --with-http_ssl_module \
            --add-dynamic-module=/path/to/ngx_http_mtproto_module
make modules
# Copy the .so to nginx modules directory
sudo cp objs/ngx_http_mtproto_module.so /usr/lib/nginx/modules/
```

Then add `load_module modules/ngx_http_mtproto_module.so;` to `nginx.conf`.

### With nginx from source (static)

```bash
./configure --add-module=/path/to/ngx_http_mtproto_module \
            --with-http_ssl_module \
            ...
make && make install
```

### Docker

```bash
docker build -t nginx-mtproto .
docker run -d --name nginx-mtproto \
    --network=host \
    -v /etc/letsencrypt:/etc/letsencrypt:ro \
    nginx-mtproto
```

## Configuration

Add directives to a `server` block that already has `ssl` enabled:

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    server_name example.com;

    # Enable MTProto proxy
    mtproto_proxy          on;
    mtproto_proxy_secret   <32-char hex secret>;
    mtproto_proxy_timeout  30s;

    # Telegram datacenters
    mtproto_proxy_dc  1  149.154.175.50:443;
    mtproto_proxy_dc  2  149.154.167.51:443;
    mtproto_proxy_dc  3  149.154.175.100:443;
    mtproto_proxy_dc  4  149.154.167.91:443;
    mtproto_proxy_dc  5  91.108.56.128:443;
    mtproto_proxy_dc_default 2;

    # Regular website / reverse proxy — served to non-MTProto visitors
    location / {
        root /var/www/html;
    }
}
```

### Directives

| Directive | Context | Description |
|---|---|---|
| `mtproto_proxy` | server | `on` / `off` — enable the module |
| `mtproto_proxy_secret` | server | 16-byte hex secret (32 hex chars) |
| `mtproto_proxy_timeout` | server | Idle timeout for relay connections (default `60s`) |
| `mtproto_proxy_dc` | server | `<id> <ip:port>` — add a Telegram datacenter |
| `mtproto_proxy_dc_default` | server | Default DC id for connections without a DC hint |

### Generating a secret

```bash
openssl rand -hex 16
```

### Client link

After setup, give users a `tg://proxy` link:

```
tg://proxy?server=<YOUR_IP>&port=443&secret=ee<SECRET><DOMAIN_HEX>
```

The `ee` prefix enables FakeTLS mode. `<DOMAIN_HEX>` is the hex-encoded SNI domain (e.g. `example.com` → `6578616d706c652e636f6d`).

```bash
# Generate the link
SECRET="your32hexcharsecret"
DOMAIN="example.com"
DOMAIN_HEX=$(echo -n "$DOMAIN" | xxd -p)
echo "tg://proxy?server=YOUR_IP&port=443&secret=ee${SECRET}${DOMAIN_HEX}"
```

## Why this approach

Most MTProto proxies (mtg, mtproto-proxy) run as standalone daemons on a dedicated port. This module embeds the proxy directly into nginx, so:

- **Port 443 only** — no unusual open ports, looks like a normal HTTPS server
- **Real website** — DPI sees a valid TLS certificate and actual web content on the same endpoint
- **No extra processes** — the proxy lives inside the nginx worker, managed by nginx lifecycle
- **Zero overhead for normal traffic** — non-MTProto connections are untouched thanks to `MSG_PEEK`

## License

MIT
