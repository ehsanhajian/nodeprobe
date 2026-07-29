# Dapptility — Personal Scanner Tool Scope

**Domain:** `dapptility.com` (optional host; local-first)  
**Document version:** 1.0  
**Product type:** Personal professional multi-scanner — Web, EVM JSON-RPC, and smart contracts  
**Audience:** Operator only (you). No public signup, payments, marketing, or outbound sales.

---

## 1. Product Definition

Dapptility is a personal security assessment console for Web3 projects you operate or are authorized to review. It combines three scanners:

1. **Web** — external HTTP/TLS posture of project websites and related hosts
2. **RPC** — external EVM JSON-RPC infrastructure (existing engine; deepen over time)
3. **Smart contract** — on-chain contract surface via RPC (bytecode, proxies, ownership, dangerous patterns)

No agents, SSH, or internal credentials. Local admin auth only. Reports are private to you.

### Explicitly out of scope

- Landing pages, pricing, sample-report marketing
- Public free-scan / self-service accounts
- USDC or any payment checkout
- Outbound lead discovery as a sales pipeline
- Responsible-disclosure CRM / outreach campaigns
- Legal/policy pages for a public SaaS

Discovery sync and outreach drafts that already exist may be kept only if useful as optional personal inventory helpers; they are not product goals.

---

## 2. Core Workflows

### 2.1 Project workspace

- Create a **project** (name, notes, optional website).
- Attach targets of three kinds:
  - Website URL(s)
  - HTTP RPC endpoint(s)
  - Contract address(es) + chain ID (optional ABI/source links)
- Run any scanner against selected targets; store history.
- View unified findings and export HTML/PDF reports for yourself.

### 2.2 Scan profiles (personal)

| Profile | Intent | Budgets |
|---|---|---|
| `Quick` | Fast pass | ≤40 requests, 2 rps, 60s |
| `Standard` | Default personal assessment | ≤80 requests, 3 rps, 120s |
| `Deep` | Thorough authorized pass | ≤200 requests, 5 rps, 300s; expensive namespace calls allowed |

Aliases for CLI/compat: `Free`→`Quick`, `Outbound`→`Standard`, `Authorized-Full`→`Deep`. No paywall gating.

### 2.3 Safety (always on)

- SSRF / private IP / metadata / localhost blocking (configurable override for lab targets you own)
- Per-profile request, RPS, and duration caps
- Global kill switch
- Clear scope labels on every report (what was / was not done)
- No exploitation payloads in default profiles

---

## 3. Web Scanner

External, non-intrusive checks against project websites:

- TLS certificate validity, chain, expiry, protocol/cipher hygiene (passive where possible)
- Security headers: HSTS, CSP, X-Frame-Options / frame-ancestors, Referrer-Policy, Permissions-Policy
- Cookie flags on Set-Cookie responses observed during crawl
- CORS misconfiguration signals on same-origin/API probes you configure
- `security.txt`, robots.txt, well-known paths
- Redirect chains and mixed-content hints
- Server / framework disclosure headers
- Optional shallow crawl of same-origin links within a hard page budget

Findings use the same severity/confidence model as RPC.

---

## 4. RPC Scanner (existing — deepen)

Keep and improve the current EVM JSON-RPC engine:

- Chain ID / identity / client version
- Expected public surface vs privileged namespaces
- TLS / CORS / HTTP hygiene on the RPC URL
- Third-party provider detection (informational for personal use; optional skip)
- Deeper Authorized/Deep rules over time (rate-limit behavior, expensive namespaces when explicitly allowed)
- WebSocket RPC (later)

CLI: `dapptility-scan scan <rpc-url> ...`

---

## 5. Smart Contract Scanner

Given chain + address (and optional RPC):

- Resolve code presence (`eth_getCode`); flag EOAs vs contracts
- Proxy detection (EIP-1967, EIP-1822, minimal proxy / EIP-1167 patterns)
- Implementation / admin / owner slot reads when patterns match
- Fetch verified source/ABI via Sourcify (and optional explorer APIs when keyed)
- Heuristic flags: `SELFDESTRUCT`, `DELEGATECALL` in bytecode, missing access control patterns when ABI available
- Common interface detection (ERC-20/721/1155, Ownable, AccessControl, UUPS/Transparent)
- Compare bytecode to known compiler metadata when available
- Never auto-broadcast transactions; read-only RPC only

CLI: `dapptility-scan contract <address> --chain <id> --rpc <url> ...`

---

## 6. Console UX (personal, professional)

- Single admin console (existing Basic auth is fine for MVP)
- Dashboard: recent scans, open high/critical findings, projects
- Project detail: web / RPC / contract targets side by side
- Scan runner: pick target type + profile; live status; findings table
- Report viewer + private token links (already built) for sharing with collaborators you choose
- Dense, technical UI — no marketing copy, no pricing CTAs
- Keyboard-friendly lists; clear severity filters

---

## 7. Data Model (delta)

Extend existing projects/endpoints/scans/findings:

- `TargetKind`: `website` | `rpc` | `contract`
- Contract fields: `address`, `chain_id`, `abi_json` (optional), `source_ref` (optional)
- Website fields: `url`, optional crawl budget
- Findings tagged with scanner module: `web` | `rpc` | `contract`
- Reports can aggregate one or more scans for a project

---

## 8. MVP Definition of Done (personal tool)

- [ ] Docs and README describe personal multi-scanner (no SaaS/marketing language)
- [ ] Projects support website, RPC, and contract targets
- [ ] Web scanner produces findings for a real HTTPS site (headers + TLS + security.txt at minimum)
- [ ] Existing RPC scanner runs from console and CLI unchanged in quality
- [ ] Contract scanner: code presence, proxy hints, basic ABI/Sourcify enrichment, HTML findings
- [ ] Unified findings list and report export for a project
- [ ] No public signup, payments, or outbound sales flows required
- [ ] Safety limits and kill switch still enforced
- [ ] Tests for new web and contract rule modules

---

## 9. Later (not MVP)

- WebSocket RPC scanning
- Deeper bytecode symbolic / Slither-class analysis (optional local tool integration)
- Multi-chain batch contract inventory from a deployer address
- Diff / re-scan alerts (email or webhook to yourself)
- Lab-mode private-network override with explicit confirm

---

## 10. Scope-Control Rule

If a feature only exists to acquire customers, take payment, or run outbound sales, do not build it. Prefer depth and reliability of the three scanners and a clean personal console.
