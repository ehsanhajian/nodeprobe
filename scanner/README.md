# Scanner

Personal multi-scanner engines + CLI: web, multi-chain RPC (EVM / Solana / Substrate / Cosmos), and EVM contracts.

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

# List rules (rpc | evm | solana | substrate | cosmos | web | contract | all)
dapptility-scan rules --module all

# Auto-detect RPC family
dapptility-scan rpc https://api.mainnet-beta.solana.com
dapptility-scan rpc https://rpc.example.com --family evm

# Explicit family commands
dapptility-scan scan https://rpc.example.com          # EVM
dapptility-scan solana https://api.mainnet-beta.solana.com
dapptility-scan substrate https://rpc.polkadot.io
dapptility-scan cosmos https://rpc.cosmos.directory:443

# Same via auto-detect / --family
dapptility-scan rpc https://api.mainnet-beta.solana.com
dapptility-scan rpc https://rpc.polkadot.io --family substrate
dapptility-scan rpc https://rpc.cosmos.directory:443 --family cosmos

# Website + EVM contract
dapptility-scan web https://example.com
dapptility-scan contract 0x… --rpc https://rpc.example.com --chain 1

# Machine-readable JSON (compact or indented)
dapptility-scan web https://example.com --json
dapptility-scan web https://example.com --json --pretty

# Deep profile + optional third-party provider block (EVM)
dapptility-scan scan https://rpc.example.com --profile Deep --block-providers
```

Human-readable report is the default on stdout (ANSI colors when stdout is a TTY; honor `NO_COLOR` / `FORCE_COLOR`, or pass `--color` / `--no-color`). Use `--json` for machine output. Exit code `2` means the scan was blocked/aborted for safety (unsafe target, provider block, unknown family, or kill switch).

## Safety

- Multi-chain RPC: EVM (any chain ID), Solana, Substrate/Polkadot, Cosmos/Tendermint
- Adaptive escalation on Standard/Deep after High/Critical hits (confirm impact / sibling methods; budgeted)
- EVM names from a bundled [Chainlist](https://chainid.network) snapshot; unknown IDs use `Chain <id>`
- SSRF / private IP / metadata / localhost blocking
- Redirect refusal to unsafe targets
- Per-profile request, RPS, and duration budgets (`Quick` / `Standard` / `Deep`)
- Global kill switch: create `/tmp/dapptility-scan-kill` or set `DAPPILITY_KILL_SWITCH`
- Presence-only privileged namespace probes on Quick/Standard (no expensive payloads)
- Expected public surface labeled separately from findings

## Tests

```bash
pytest -q
```
