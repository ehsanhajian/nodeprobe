# Scanner

Personal multi-scanner engines + CLI. RPC and web are available; smart contracts next.

See [docs/FEATURE_LIST.md](../docs/FEATURE_LIST.md).

## Setup

```bash
cd scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## CLI

```bash
# List profiles and budgets
dapptility-scan profiles

# List rules (rpc | web | all)
dapptility-scan rules --module all

# Scan an RPC endpoint (Free profile by default)
dapptility-scan scan https://rpc.example.com --pretty

# Scan a website
dapptility-scan web https://example.com --pretty

# Outbound profile (blocks known third-party RPC providers)
dapptility-scan scan https://rpc.example.com --profile Outbound --pretty
```

JSON is written to stdout. Exit code `2` means the scan was blocked/aborted for safety (unsafe target, unsupported chain, provider block, or kill switch).

## Safety

- SSRF / private IP / metadata / localhost blocking
- Redirect refusal to unsafe targets
- Per-profile request, RPS, and duration budgets
- Global kill switch: create `/tmp/dapptility-scan-kill` or set `DAPPILITY_KILL_SWITCH`
- Presence-only privileged namespace probes on Free/Outbound (no expensive payloads)
- Expected public surface labeled separately from findings

## Tests

```bash
pytest -q
```
