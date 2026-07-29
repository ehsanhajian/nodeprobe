# Development Guide

## Current status

| Piece | Status | Location |
|---|---|---|
| Multi-chain RPC CLI (EVM / Solana / Substrate / Cosmos) | **Done** | `scanner/` |
| Human + colored CLI reports (`--json` opt-in) | **Done** | `scanner/` |
| Console, persistence, reports | **Done** | `app/` |
| ChainList discovery (optional inventory) | Present | `app/` — optional |
| Web scanner | **Done** | `scanner/` |
| EVM smart contract scanner | **Done** | `scanner/` |
| Multi-target projects + unified reports | **Done** | `app/` |

Product scope: [FEATURE_LIST.md](FEATURE_LIST.md) (personal tool — no SaaS/marketing).  
Backlog: [GitHub issues](https://github.com/ehsanhajian/dapptility/issues) (label `personal-tool`).

## Prerequisites

- Python 3.10+
- `python3-venv` (on Ubuntu: `sudo apt install python3.10-venv`)

## Scanner

Python package + CLI for web, multi-chain RPC, and EVM contracts.

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
dapptility-scan rpc <URL>         # multi-chain RPC (auto-detect)
dapptility-scan scan <URL>        # EVM RPC (default: Quick)
dapptility-scan solana <URL>
dapptility-scan substrate <URL>
dapptility-scan cosmos <URL>
dapptility-scan web <URL>         # website HTTP/TLS scan
dapptility-scan contract <address> --chain <id> --rpc <url>
```

Options:

- `--profile Quick|Standard|Deep` (aliases: Free→Quick, Outbound→Standard, Authorized-Full→Deep)
- `--family auto|evm|solana|substrate|cosmos` — for `rpc` command
- `--block-providers` — block known third-party RPC hosts (EVM only)
- `--json` — machine-readable JSON instead of the human report
- `--pretty` — with `--json`, indent JSON (human report is the default without `--json`)
- `--color` / `--no-color` — force or disable ANSI colors in the human report

Exit codes:

- `0` — scan completed
- `2` — blocked/aborted (unsafe target, provider block, unknown family, kill switch)

### Architecture

```
scanner/src/dapptility_scanner/
  cli.py          CLI entrypoint
  report.py       Human-readable (colorized) scan report formatting
  engine.py       EVM scan orchestration
  multichain/     Solana / Substrate / Cosmos engines + auto-detect
  profiles.py     Profile limits
  safety.py       SSRF and target validation
  rpc.py          Budgeted JSON-RPC client
  chains.py       EVM chain ID → name (bundled Chainlist snapshot)
  data/           Package data (chains_mini.json)
  providers.py    Third-party provider detection
  killswitch.py   Global emergency stop
  scoring.py      0–100 security score
  web_engine.py   Website scanner
  contract_engine.py  EVM contract scanner
  rules/          Pluggable EVM + web rule implementations
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
