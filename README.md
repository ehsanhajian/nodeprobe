# Dapptility

Personal professional scanner for **web**, **multi-chain RPC**, and **EVM smart contracts**.

Local-first console for projects you operate or are authorized to assess. No public signup, payments, or marketing surface.

## Overview

| Module | What it assesses |
|---|---|
| **Web** | External HTTP/TLS posture (headers, certificate, security.txt, robots.txt, …) |
| **RPC** | Public RPC surface for **EVM**, **Solana**, **Substrate/Polkadot**, and **Cosmos/Tendermint** |
| **Smart contract** | Read-only EVM on-chain surface (code, proxies, bytecode heuristics, Sourcify/ABI hints) |

Projects hold website, RPC, and contract targets. Findings can be reviewed together and exported as a multi-module HTML/PDF report.

**Profiles:** `Quick` · `Standard` · `Deep` (aliases: Free→Quick, Outbound→Standard, Authorized-Full→Deep)

**Safety:** SSRF / private-IP blocking, per-profile request budgets, kill switch, clear report scope (what was / was not done).

## Status

Personal-tool MVP: web + multi-chain RPC + EVM contracts, console targets, unified findings/reports.

Optional: ChainList RPC inventory sync (off by default — set `DAPPILITY_DISCOVERY_ENABLED=true`).

## Repository layout

```
docs/           Scope and development docs
scanner/        Scan engines + CLI
app/            Personal console, persistence, reports
deploy/         Caddy config for Docker
```

## Quick start

### Scanner CLI

```bash
cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

dapptility-scan profiles
dapptility-scan rules --module all

# Auto-detect RPC family (evm | solana | substrate | cosmos)
dapptility-scan rpc https://api.mainnet-beta.solana.com
dapptility-scan rpc https://rpc.polkadot.io --family substrate
dapptility-scan scan https://rpc.example.com --profile Standard   # EVM
dapptility-scan solana https://api.mainnet-beta.solana.com
dapptility-scan web https://example.com
dapptility-scan contract 0x… --rpc https://rpc.example.com --chain 1

# Machine-readable JSON
dapptility-scan web https://example.com --json --pretty

pytest -q
```

Exit code `2` means the scan was blocked/aborted (unsafe target, kill switch, unknown RPC family, provider block with `--block-providers`, etc.).

See [scanner/README.md](scanner/README.md).

### Console

```bash
pip install -e "./scanner[dev]" -e "./app[dev]"
export DAPPILITY_ADMIN_PASSWORD=your-secure-password
dapptility-admin
```

Open http://localhost:8000/admin (`admin` / your password).

- Projects → add **web** / **rpc** / **contract** targets → run scans
- Project findings (filter by module / severity)
- **Build project report** for a combined assessment

See [app/README.md](app/README.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

### Production (Docker + Caddy)

```bash
cp .env.example .env   # set admin password and secrets
docker compose up -d --build
```

See [docs/DOCKER.md](docs/DOCKER.md).

## Docs

| Doc | Purpose |
|---|---|
| [docs/FEATURE_LIST.md](docs/FEATURE_LIST.md) | Product scope (personal tool) |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Architecture and setup |
| [docs/DOCKER.md](docs/DOCKER.md) | Production deploy |

## License

Proprietary — all rights reserved unless otherwise stated.
