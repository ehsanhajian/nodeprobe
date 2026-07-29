# Development Guide

## Current status

| Milestone | Status | Location |
|---|---|---|
| M1 — Scanner CLI | **Complete** | `scanner/` |
| M2 — Reports and Admin | **Complete** | `app/` |
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

## Admin app (M2)

FastAPI admin panel with SQLite persistence, scan orchestration, finding review, and report delivery.

### Install and run

```bash
pip install -e "./scanner[dev]" -e "./app[dev]"
export DAPPILITY_ADMIN_PASSWORD=your-secure-password
dapptility-admin
```

Admin UI: http://localhost:8000/admin (HTTP Basic `admin` / password)

### Features

- Project and HTTP endpoint CRUD with third-party provider flags
- Scan execution (Free / Outbound / Authorized-Full) from admin
- Outbound finding review: confirm, reject, false positive
- HTML and PDF reports with What we did / did not do
- Private report links at `/r/{token}`
- Raw scan JSON retention (30 days, admin-only access)
- Audit log for admin actions

### App layout

```
app/src/dapptility_app/
  main.py           FastAPI application
  database.py       SQLAlchemy models
  routes/           Admin and public report routes
  services/         Scan orchestration, reports, persistence
  templates/        Admin UI and report HTML
```

### Tests

```bash
cd app && pytest -q
```

## Next up (M3)

- Public landing page and free scan flow
- User accounts with magic-link auth
- Abuse budgets and rate limiting

See GitHub milestone [M3 — Public Self-service](https://github.com/ehsanhajian/dapptility/milestone/3).

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
