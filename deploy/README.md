# Deploying Attach Open Score as a hosted verdict API

This directory holds everything needed to run `attach-open-score serve` as an
internet-facing, authenticated, TLS-terminated service.

## Security model

The verdict service binds **loopback only** and is fronted by nginx for TLS.
Authentication is a Bearer token verified **inside the service** (constant-time),
so a reverse-proxy misconfiguration cannot expose the API unauthenticated. The
service additionally **refuses to bind a non-loopback address unless a token is
set**, making accidental open exposure impossible.

Hardening summary:

| Risk | Mitigation |
|------|------------|
| Unauthenticated access (S1) | Bearer token required on `/v0/*`; loopback-bind guard refuses open exposure without a token |
| Cache disk/CPU exhaustion (S2) | Cache capped at 50k entries (FIFO eviction); `MemoryMax`/`TasksMax` in systemd |
| Slowloris / idle sockets (S3) | `ReadTimeout`/`WriteTimeout`/`IdleTimeout` in the service |
| Request flooding / OSV amplification (S4) | App rate limit (`--rate-limit 120/min`) |
| Plaintext transport (S5) | nginx + Let's Encrypt (certbot) TLS with HTTP->HTTPS redirect |

The live deployment runs at `https://score.attach.dev/v0/verdict`.

## One-time server setup (run as root)

```bash
# 1. Dedicated unprivileged user + state dir
useradd --system --no-create-home --shell /usr/sbin/nologin attach-score
install -d -o attach-score -g attach-score -m 0750 /var/lib/attach-open-score
install -d -m 0750 /etc/attach-open-score
install -d -m 0755 /var/log/caddy

# 2. Generate the API token and write the env file (root-only readable)
umask 077
printf 'ATTACH_OPEN_SCORE_API_TOKEN=%s\n' "$(openssl rand -hex 32)" \
  > /etc/attach-open-score/score.env
# Keep a copy of that token for clients; it is the API key.

# 3. Install the binary (built for the server's GOOS/GOARCH — see below)
install -o root -g root -m 0755 attach-open-score /usr/local/bin/attach-open-score

# 4. Install + start the service
cp attach-open-score.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now attach-open-score
systemctl status attach-open-score --no-pager

# 5. Front it with nginx + TLS (DNS for the hostname must resolve to this host)
cp nginx-score.attach.dev.conf /etc/nginx/sites-available/score.attach.dev
ln -sf /etc/nginx/sites-available/score.attach.dev /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot --nginx -d score.attach.dev --redirect   # issues cert + flips to HTTPS
```

## Building the server binary

Cross-compile from a dev machine for the server's platform (commonly linux/amd64):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o attach-open-score ./cmd/attach-open-score
```

`CGO_ENABLED=0` yields a static binary with no libc dependency.

## Smoke test (from the server)

```bash
curl -s localhost:8757/health                       # {"status":"ok"} — no auth
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST localhost:8757/v0/verdict \
  -d '{"ecosystem":"npm","name":"left-pad","version":"1.3.0"}'   # 401 (no token)
curl -s -X POST localhost:8757/v0/verdict \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ecosystem":"npm","name":"left-pad","version":"1.3.0"}'   # 200 + verdict JSON
```

## Pointing Attach Guard at the hosted service

```bash
export ATTACH_OPEN_SCORE_ENDPOINT=https://score.attach.dev/v0/verdict
export ATTACH_OPEN_SCORE_API_TOKEN=<token>
# Guard's open-score HTTP provider sends Authorization: Bearer <token>.
```
