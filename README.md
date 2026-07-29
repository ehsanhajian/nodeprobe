# Dapptility

Personal professional scanner for **web**, **EVM JSON-RPC**, and **smart contracts**.

Local-first console for projects you operate or are authorized to assess. No public signup, payments, or marketing surface.

## Overview

Three scanners, one workspace:

| Module | What it assesses |
|---|---|
| **Web** | External HTTP/TLS posture of project sites (headers, TLS, security.txt, …) |
| **RPC** | Public EVM JSON-RPC endpoints from an external attacker’s view |
| **Smart contract** | On-chain contract surface via read-only RPC (code, proxies, ABI/Sourcify, heuristics) |

Safety defaults stay on: SSRF protections, request budgets, kill switch, clear report scope.

## Repository layout

```
docs/           Scope and development docs
scanner/        Scan engines + CLI
app/            Personal console, persistence, reports
```

## Scope

See [docs/FEATURE_LIST.md](docs/FEATURE_LIST.md). Build order:

1. RPC scanner CLI — **done**
2. Console, projects, reports — **done** (RPC-focused today)
3. Reposition as personal multi-scanner (docs + target model)
4. Web scanner module
5. Smart contract scanner module
6. Unified project findings and reports

## Development

### Scanner

```bash
cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
dapptility-scan scan https://rpc.example.com --pretty
pytest -q
```

See [scanner/README.md](scanner/README.md).

### Console

```bash
pip install -e "./scanner[dev]" -e "./app[dev]"
export DAPPILITY_ADMIN_PASSWORD=your-secure-password
dapptility-admin
```

Open http://localhost:8000/admin (`admin` / your password).

See [app/README.md](app/README.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

### Production (Docker + Caddy)

```bash
cp .env.example .env   # set admin password and secrets
docker compose up -d --build
```

See [docs/DOCKER.md](docs/DOCKER.md).

## License

Proprietary — all rights reserved unless otherwise stated.
