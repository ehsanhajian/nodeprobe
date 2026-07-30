# Dapptility — CLI Scanner Scope

**Document version:** 1.1  
**Product type:** CLI multi-scanner — website, multi-chain RPC, and EVM smart contracts  
**Audience:** Operators assessing systems they own or are authorized to test.

---

## 1. Product Definition

Dapptility is a local CLI (`dapptility-scan`) for security assessment of Web3-related surfaces:

1. **Website** — external HTTP/TLS posture
2. **RPC** — public RPC for **EVM**, **Solana**, **Substrate/Polkadot**, and **Cosmos/Tendermint**
3. **Smart contract** — EVM on-chain surface via read-only RPC (bytecode, proxies, ownership hints)

No web console, no agents, no SSH, no cloud account. Findings print to the terminal (or `--json`).

### Explicitly out of scope

- Web admin / SaaS console
- Landing pages, pricing, public free-scan
- Payments / signup
- Outbound lead discovery / sales CRM
- Non-EVM program/contract deep analysis (Solana programs, etc.) — later

---

## 2. Workflows

### Profiles

| Profile | Intent | Budgets |
|---|---|---|
| `Quick` | Fast pass | ≤40 requests, 2 rps, 60s |
| `Standard` | Default assessment | ≤80 requests, 3 rps, 120s; escalation on |
| `Deep` | Thorough authorized pass | ≤200 requests, 5 rps, 300s; richer escalation |

Aliases: `Free`→`Quick`, `Outbound`→`Standard`, `Authorized-Full`→`Deep`.

### Safety (always on)

- SSRF / private IP / metadata / localhost blocking
- Per-profile request, RPS, and duration caps
- Global kill switch
- Presence-only / confirmation probes — no default exploit or funded-tx payloads
- Adaptive escalation on Standard/Deep (bounded follow-ups after High/Critical or key Medium hits)

---

## 3. Website scanner

CLI: `dapptility-scan web <url>`

- TLS certificate validity / expiry
- Security headers (HSTS, CSP, frame controls, …)
- `security.txt`, robots.txt
- Server / framework disclosure
- Escalation: cleartext HTTP check, framing/inline-script follow-ups, sensitive-path spot-checks

---

## 4. RPC scanner (multi-chain)

| Family | CLI |
|---|---|
| EVM | `scan` / `rpc --family evm` |
| Solana | `solana` / `rpc --family solana` |
| Substrate / Polkadot | `substrate` / `rpc --family substrate` |
| Cosmos / Tendermint | `cosmos` / `rpc --family cosmos` |

Auto-detect: `dapptility-scan rpc <url>`.

Escalation examples: privileged namespace → confirm impact → sibling / send-path probes.

---

## 5. Smart contract scanner

CLI: `dapptility-scan contract <address> --rpc <url> [--chain <id>]`

- Code presence, proxy patterns, bytecode heuristics (SELFDESTRUCT / DELEGATECALL)
- Sourcify verification hints, interface/Ownable hints
- Escalation: fetch implementation bytecode, `owner()` eth_call

---

## 6. Non-goals

Do not build features whose only purpose is customer acquisition, payments, or outbound sales. Prefer scanner depth and a reliable CLI.
