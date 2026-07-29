# Development Guide

## Current status

| Piece | Status | Location |
|---|---|---|
| RPC scanner CLI | **Done** | `scanner/` |
| Console, persistence, reports | **Done** (RPC-focused) | `app/` |
| ChainList discovery (optional inventory) | Present | `app/` — de-emphasize per #38 |
| Web scanner | Planned | #34 |
| Smart contract scanner | Planned | #35 |
| Multi-target projects + unified reports | Planned | #32, #37 |

Product scope: [FEATURE_LIST.md](FEATURE_LIST.md) (personal tool — no SaaS/marketing).  
Backlog: [GitHub issues](https://github.com/ehsanhajian/dapptility/issues) (label `personal-tool`).

## Prerequisites

- Python 3.10+
- `python3-venv` (on Ubuntu: `sudo apt install python3.10-venv`)

## Scanner

Python package + CLI. RPC scan works today; web and contract modules are next.

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
dapptility-scan scan <URL>        # RPC scan (default: Quick)
```

Planned:

```bash
dapptility-scan web <URL>
dapptility-scan contract <address> --chain <id> --rpc <url>
```

Options (RPC today):

- `--profile Quick|Standard|Deep` (aliases: Free→Quick, Outbound→Standard, Authorized-Full→Deep)
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
  profiles.py     Profile limits
  safety.py       SSRF and target validation
  rpc.py          Budgeted JSON-RPC client
  chains.py       Supported EVM chain registry
  providers.py    Third-party provider detection
  killswitch.py   Global emergency stop
  scoring.py      0–100 security score
  rules/          Pluggable rule implementations
```

### RPC rules (current)

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
- Presence-only namespace probes on lighter profiles (no expensive payloads)
- Optional third-party provider blocking
- Kill switch file: `/tmp/dapptility-scan-kill` or `DAPPILITY_KILL_SWITCH` env var

### Tests

```bash
cd scanner
source .venv/bin/activate
pytest -q
```

CI runs the same test suite on push/PR to `main`.

## Console (app)

FastAPI personal console with SQLite persistence, scan orchestration, and report delivery.

### Install and run

```bash
pip install -e "./scanner[dev]" -e "./app[dev]"
export DAPPILITY_ADMIN_PASSWORD=your-secure-password
dapptility-admin
```

UI: http://localhost:8000/admin (HTTP Basic `admin` / password)

### Features today

- Project and HTTP RPC endpoint CRUD
- Scan execution from admin
- Finding review (confirm / reject / false positive)
- HTML and PDF reports with What we did / did not do
- Private report links at `/r/{token}`
- Raw scan JSON retention (30 days, admin-only)
- Optional ChainList discovery inbox (sales-oriented; retire from primary nav — #38)

```
app/src/dapptility_app/
  main.py           FastAPI application
  database.py       SQLAlchemy models
  routes/           Admin and private report routes
  services/         Scan orchestration, reports, persistence
  templates/        Console UI and report HTML
```

### Tests

```bash
cd app && pytest -q
```

## Next up

See epic [#30](https://github.com/ehsanhajian/dapptility/issues/30) and DoD [#40](https://github.com/ehsanhajian/dapptility/issues/40).

Suggested order: docs polish (#31) → targets (#32) → profiles (#33) → web (#34) + contract (#35) → wire-up (#36) → unified reports (#37) → UI cleanup (#38).

## Git workflow

Repository: https://github.com/ehsanhajian/dapptility

```bash
git checkout -b feature/my-change
# ... edit ...
pytest -q   # from scanner/ and app/ with venv active
git add -A && git commit -m "..."
git push -u origin feature/my-change
gh pr create
```
