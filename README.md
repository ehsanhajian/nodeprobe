# Dapptility

Web3 RPC security scanner and productized security assessment platform.

**Domain:** [dapptility.com](https://dapptility.com)

## Overview

Dapptility assesses the external security posture of EVM JSON-RPC infrastructure from an attacker's perspective — without agents, SSH, or internal credentials.

Two acquisition paths:

1. **Outbound** — limited external review, private preliminary report, responsible disclosure outreach
2. **Self-service** — free scan → DNS ownership verification → paid full report

## Repository layout

```
docs/           Product and planning documents
scanner/        EVM RPC scan engine (Milestone 1)
```

## MVP focus

See [docs/FEATURE_LIST.md](docs/FEATURE_LIST.md) for the full product scope. Current build order:

1. Scanner CLI with `Free` and `Outbound` profiles — **done** (see [scanner/README.md](scanner/README.md))
2. Reports and admin panel
3. Public self-service (landing, accounts, free scan)
4. DNS verification and USDC payment
5. First sales

## Development

### Scanner (Milestone 1)

```bash
cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
dapptility-scan scan https://rpc.example.com --pretty
pytest -q
```

See [scanner/README.md](scanner/README.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

Application and admin code will land under `app/` in later milestones.

## Policies

Legal and policy pages (Terms, Privacy, Acceptable Use, Scan Safety) will be added before public launch.

## License

Proprietary — all rights reserved unless otherwise stated.
