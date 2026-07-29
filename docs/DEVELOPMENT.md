# Development Guide

## Current status

| Milestone | Status | Location |
|---|---|---|
| M1 — Scanner CLI | **Complete** | `scanner/` |
| M2 — Reports and Admin | Not started | `app/` (planned) |
| M3 — Public Self-service | Not started | `app/` (planned) |
| M4 — Verification and Payment | Not started | `app/` (planned) |
| M5 — First Sales | Not started | — |

Product scope and requirements: [FEATURE_LIST.md](FEATURE_LIST.md)

## Prerequisites

- Python 3.10+
- `python3-venv` (on Ubuntu: `sudo apt install python3.10-venv`)

## Scanner (M1)

The scanner is a Python package with a CLI that outputs JSON scan results.

### Install

```bash
cd scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Commands

```bash
dapptility-scan profiles          # scan profile budgets
dapptility-scan rules             # registered rule catalog
dapptility-scan scan <URL>        # run a scan (default: Free profile)
```

Options:

- `--profile Free|Outbound|Authorized-Full`
- `--block-providers` — block known third-party RPC hosts
- `--pretty` — formatted JSON output

Exit codes:

- `0` — scan completed
- `2` — blocked/aborted (unsafe target, unsupported chain, provider block, kill switch)

### Architecture

```
scanner/src/dapptility_scanner/
  cli.py          CLI entrypoint
  engine.py       Scan orchestration
  profiles.py     Free / Outbound / Authorized-Full limits
  safety.py       SSRF and target validation
  rpc.py          Budgeted JSON-RPC client
  chains.py       Supported EVM chain registry
  providers.py    Third-party provider detection
  killswitch.py   Global emergency stop
  scoring.py      0–100 security score
  rules/          Pluggable rule implementations
```

### Rules (15)

| ID | Category |
|---|---|
| EVM-IDENT-001–003 | Network identity |
| EVM-CLIENT-001–002 | Client / header exposure |
| EVM-HTTP-001–002 | Content-Type, CORS |
| EVM-TLS-001 | TLS certificate |
| EVM-SURFACE-001 | Expected public RPC surface |
| EVM-NS-* | Privileged namespace presence probes |

### Safety controls

- Block localhost, private/reserved IPs, and cloud metadata ranges
- DNS resolution validation (reject private resolved addresses)
- No redirect following to unvalidated targets
- Per-profile request count, RPS, and duration ceilings
- Presence-only namespace probes on Free/Outbound (no expensive payloads)
- Outbound profile blocks Alchemy, Ankr, Infura, QuickNode, LlamaNodes, and others
- Kill switch file: `/tmp/dapptility-scan-kill` or `DAPPILITY_KILL_SWITCH` env var

### Tests

```bash
cd scanner
source .venv/bin/activate
pytest -q
```

CI runs the same test suite on push/PR to `main`.

## Next up (M2)

- Persist projects, endpoints, scans, and findings
- Admin panel to run scans and review outbound results
- HTML/PDF reports with scope disclosure
- Private report links and evidence retention defaults

See GitHub milestone [M2 — Reports and Admin](https://github.com/ehsanhajian/dapptility/milestone/2).

## Git workflow

Repository: https://github.com/ehsanhajian/dapptility

```bash
git checkout -b feature/my-change
# ... edit ...
pytest -q   # from scanner/ with venv active
git add -A && git commit -m "..."
git push -u origin feature/my-change
gh pr create
```

Remote uses SSH: `git@github.com:ehsanhajian/dapptility.git`
