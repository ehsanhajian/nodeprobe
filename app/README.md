# App

Admin panel, persistence, and report delivery — Milestone 2.

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

## Features (M2)

- Project and HTTP endpoint CRUD
- Third-party provider detection and scan blocking
- Scan execution from admin (Free / Outbound / Authorized-Full)
- Outbound finding review (confirm / reject / false positive)
- HTML and PDF reports with scope disclosure
- Private report links (`/r/{token}`)
- Raw evidence retention with admin-only access

## Tests

```bash
pytest -q
```
