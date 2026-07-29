# App

Personal console, persistence, and report delivery.

## Setup

```bash
cd scanner && python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
cd ../app && pip install -e ".[dev]"
```

## Run

```bash
export DAPPILITY_ADMIN_PASSWORD=your-secure-password
dapptility-admin
```

Open http://localhost:8000/admin (HTTP Basic: `admin` / your password).

## Environment

| Variable | Default | Description |
|---|---|---|
| `DAPPILITY_ADMIN_PASSWORD` | `changeme` | Admin HTTP Basic password |
| `DAPPILITY_DATABASE_URL` | `sqlite:///data/dapptility.db` | SQLAlchemy database URL |
| `DAPPILITY_DATA_DIR` | `data/` | Reports and raw evidence storage |
| `DAPPILITY_REPORT_BASE_URL` | `http://localhost:8000` | Base URL for private report links |
| `DAPPILITY_RAW_RETENTION_DAYS` | `30` | Raw scan JSON retention |

## Features

- Project and HTTP RPC endpoint CRUD
- Third-party provider detection (optional skip)
- Scan execution from console
- Finding review (confirm / reject / false positive)
- Project findings view (filter by module / severity)
- Project reports aggregating latest web + RPC + contract scans
- HTML and PDF reports with per-module scope disclosure
- Private report links (`/r/{token}`)
- Raw evidence retention with admin-only access

See GitHub `personal-tool` issues for remaining polish.

## Tests

```bash
pytest -q
```
