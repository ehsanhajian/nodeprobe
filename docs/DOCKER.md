# Docker deployment

Production stack: **app** (FastAPI) + **Caddy** (HTTPS reverse proxy).

## Prerequisites

- Docker and Docker Compose v2
- DNS `A` record for `dapptility.com` (and optionally `www`) pointing to this server
- Ports **80** and **443** open on the host firewall
- If using Cloudflare: set the record to **DNS only** (grey cloud) while Caddy obtains the first certificate, or use Cloudflare Full SSL with an origin certificate

## Quick start

```bash
cd /home/ubuntu/dapptility
cp .env.example .env
# Edit .env — set DAPPILITY_ADMIN_PASSWORD and DAPPILITY_SECRET_KEY
docker compose up -d --build
docker compose logs -f caddy
```

Site: https://dapptility.com  
Admin: https://dapptility.com/admin (`admin` / password from `.env`)

## SSL

Caddy obtains and renews Let's Encrypt certificates automatically using the email in `ACME_EMAIL`.

Check certificate status:

```bash
docker compose exec caddy caddy list-certificates
docker compose logs caddy | tail -50
```

## Operations

```bash
docker compose ps
docker compose logs -f app
docker compose restart app
docker compose down          # stop
docker compose up -d --build # rebuild after code changes
```

Data (SQLite DB, reports, raw scan JSON) is stored in the `dapptility-data` Docker volume.

## Environment

| Variable | Description |
|---|---|
| `DAPPILITY_DOMAIN` | Public hostname (default `dapptility.com`) |
| `DAPPILITY_REPORT_BASE_URL` | Base URL for private report links |
| `ACME_EMAIL` | Let's Encrypt registration email |
| `DAPPILITY_ADMIN_PASSWORD` | Admin panel password |
| `DAPPILITY_SECRET_KEY` | App secret key |

## Troubleshooting

**Certificate fails to issue**

- Confirm DNS points to this server's public IP: `dig +short dapptility.com`
- Confirm nothing else binds ports 80/443: `ss -tlnp | grep -E ':80|:443'`
- Check Caddy logs for ACME errors

**Cloudflare 523**

- Origin is unreachable. Point DNS to this server or configure Cloudflare origin correctly.
