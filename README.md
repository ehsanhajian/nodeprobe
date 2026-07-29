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

1. Scanner CLI with `Free` and `Outbound` profiles
2. Reports and admin panel
3. Public self-service (landing, accounts, free scan)
4. DNS verification and USDC payment
5. First sales

## Development

Project scaffolding is in progress. Scanner CLI and application code will land under `scanner/` and `app/` as milestones are implemented.

## Policies

Legal and policy pages (Terms, Privacy, Acceptable Use, Scan Safety) will be added before public launch.

## License

Proprietary — all rights reserved unless otherwise stated.
