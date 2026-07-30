# Development Guide

## Current status

| Piece | Status | Location |
|---|---|---|
| CLI multi-scanner (`dapptility-scan`) | **Done** | `scanner/` |
| Website scanner | **Done** | `scanner/` |
| Multi-chain RPC (EVM / Solana / Substrate / Cosmos) | **Done** | `scanner/` |
| EVM contract scanner | **Done** | `scanner/` |
| Human + colored reports (`--json` opt-in) | **Done** | `scanner/` |
| Adaptive escalation (Standard/Deep) | **Done** | RPC / web / contract |

Product scope: [FEATURE_LIST.md](FEATURE_LIST.md).

## Prerequisites

- Python 3.10+
- `python3-venv` (on Ubuntu: `sudo apt install python3.10-venv`)

## Install

```bash
cd scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Commands

```bash
dapptility-scan profiles
dapptility-scan rules --module all
dapptility-scan rpc <URL>              # auto-detect family
dapptility-scan scan <URL>             # EVM
dapptility-scan solana <URL>
dapptility-scan substrate <URL>
dapptility-scan cosmos <URL>
dapptility-scan web <URL>
dapptility-scan contract <address> --rpc <url> [--chain <id>]
```

Options:

- `--profile Quick|Standard|Deep`
- `--family auto|evm|solana|substrate|cosmos` (for `rpc`)
- `--block-providers` (EVM only)
- `--json` / `--pretty` / `--color` / `--no-color`

Exit codes: `0` completed · `2` blocked/aborted

## Architecture

```
scanner/src/dapptility_scanner/
  cli.py                 CLI entrypoint
  report.py              Human-readable (colorized) reports
  engine.py              EVM RPC orchestration
  web_engine.py          Website scanner
  contract_engine.py     EVM contract scanner
  escalation*.py         Finding-driven follow-ups
  multichain/            Solana / Substrate / Cosmos + auto-detect
  chains.py + data/      EVM chain ID → name (Chainlist snapshot)
  rules/                 EVM + web rules
```

## Safety controls

- Block localhost, private/reserved IPs, cloud metadata
- DNS validation, redirect policy
- Per-profile budgets
- Kill switch: `/tmp/dapptility-scan-kill` or `DAPPILITY_KILL_SWITCH`
- Escalation is confirmation-oriented (no exploit payloads)

## Tests

```bash
cd scanner
source .venv/bin/activate
pytest -q
```

CI runs the same suite on push/PR to `main`.
