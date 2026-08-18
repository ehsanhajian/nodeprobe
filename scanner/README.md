# Nodeprobe

**Local CLI security scanner for websites, multi-chain RPC nodes, and EVM smart contracts.**

Probe HTTP/TLS, JSON-RPC and GraphQL RPC, and contract posture from your terminal. Local-first for infrastructure you operate or are authorized to assess. No account. No cloud. No telemetry.

```bash
pipx install nodeprobe
nodeprobe web https://example.com
```

Homebrew and Debian/Ubuntu block `pip install` into system Python. Use [pipx](https://pipx.pypa.io/) or a virtual environment (`python3 -m venv .venv && source .venv/bin/activate && pip install nodeprobe`). Do not pass `--break-system-packages`.

Default profile is **Standard**. Use `--profile Quick` for a fast pass, or `--profile Deep` for a larger budget.

## What it covers

| Surface | What Nodeprobe looks at |
|---|---|
| **Web** | TLS, security headers (presence + HSTS/CSP policy grading), `security.txt`, `robots.txt`, server disclosure |
| **RPC** | Protocol **families**: EVM, Solana, Substrate/Polkadot, Cosmos, Aptos, Sui, Starknet, NEAR — auto-detect or `--family` |
| **Contracts** | EVM code presence, proxies, bytecode heuristics, Sourcify verification (read-only) |

EVM networks share one engine. `nodeprobe scan <rpc>` works for any EVM chain. Chain names come from a bundled [Chainlist](https://chainid.network) snapshot; unknown IDs still scan with a generic name.

## Quick start

```bash
# Website
nodeprobe web https://example.com

# EVM RPC — any EVM chain
nodeprobe scan https://rpc.example.com

# Other protocol families
nodeprobe rpc https://api.mainnet-beta.solana.com
nodeprobe substrate https://rpc.polkadot.io
nodeprobe cosmos https://rpc.cosmos.directory:443
nodeprobe aptos https://fullnode.mainnet.aptoslabs.com/v1
nodeprobe sui https://graphql.mainnet.sui.io/graphql
nodeprobe starknet https://rpc.starknet.lava.build
nodeprobe near https://rpc.mainnet.near.org

# Contract (read-only)
nodeprobe contract 0x… --rpc https://rpc.example.com --chain 1
```

Human reports are the default. Use `--html -o report.html` or `--json --pretty` for other formats.

## Safety by design

- Blocks SSRF paths: private IPs, localhost, cloud metadata
- Enforces per-profile request, RPS, and duration budgets
- Kill switch: touch `/tmp/nodeprobe-kill` or set `NODEPROBE_KILL_SWITCH`
- Escalation confirms impact — no exploit payloads, no funded transactions

**Authorized use only.** Scan systems you own or have permission to assess.

## Docs and source

Full examples, screenshots, and development setup: [github.com/ehsanhajian/nodeprobe](https://github.com/ehsanhajian/nodeprobe)

## License

[MIT](https://github.com/ehsanhajian/nodeprobe/blob/main/LICENSE)
