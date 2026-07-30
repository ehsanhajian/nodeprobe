# Dapptility

CLI scanner for **websites**, **multi-chain RPC**, and **EVM smart contracts**.

Assess infrastructure you operate or are authorized to test. Local-first — no signup, no cloud account, no payments.

## What it scans

| Command | Target |
|---|---|
| `dapptility-scan web` | HTTP/TLS posture (headers, certificate, security.txt, robots.txt, …) |
| `dapptility-scan rpc` / `scan` / `solana` / `substrate` / `cosmos` | Public RPC surface (EVM, Solana, Substrate/Polkadot, Cosmos/Tendermint) |
| `dapptility-scan contract` | Read-only EVM contract surface (code, proxies, bytecode heuristics, Sourcify) |

**Profiles:** `Quick` · `Standard` · `Deep`  
**Output:** human-readable color report by default; `--json` for machines  
**Safety:** SSRF / private-IP blocking, request budgets, kill switch, adaptive escalation on Standard/Deep (confirm impact — no exploit payloads)

## Install

```bash
cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
dapptility-scan profiles
dapptility-scan rules --module all

# Website
dapptility-scan web https://example.com --profile Standard

# Multi-chain RPC (auto-detect or explicit)
dapptility-scan rpc https://YOUR_RPC
dapptility-scan scan https://rpc.example.com --profile Standard   # EVM
dapptility-scan solana https://api.mainnet-beta.solana.com
dapptility-scan substrate https://rpc.polkadot.io
dapptility-scan cosmos https://rpc.cosmos.directory:443

# EVM contract
dapptility-scan contract 0x… --rpc https://rpc.example.com --chain 1

# Machine-readable JSON
dapptility-scan web https://example.com --json --pretty

pytest -q
```

Exit code `2` means the scan was blocked/aborted (unsafe target, kill switch, unknown RPC family, `--block-providers`, etc.).

See [scanner/README.md](scanner/README.md).

## Repository layout

```
scanner/   Scan engines + CLI (`dapptility-scan`)
docs/      Scope and development notes
```

## Docs

| Doc | Purpose |
|---|---|
| [docs/FEATURE_LIST.md](docs/FEATURE_LIST.md) | Product scope |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Architecture and setup |

## Authorized use

Only scan systems you own or have permission to assess. Misuse against third parties without authorization may be illegal.

## License

Proprietary — all rights reserved unless otherwise stated.
