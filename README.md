# Dapptility

CLI security scanner for **websites**, **multi-chain RPC**, and **EVM smart contracts**.

Scan infrastructure you operate or are authorized to assess. Local-first — no account, no cloud, no payments.

```bash
dapptility-scan web https://example.com --profile Standard
```

```
Dapptility scan report
========================================================================
Target:  https://example.com
Profile:  Standard
Score:  66/100
Duration:  4.1s · 6 request(s)
Status:  completed

Summary
------------------------------------------------------------------------
  Critical 0  High 0  Medium 2  Low 0  Info 1  Expected-surface 1

Findings (5)
------------------------------------------------------------------------
1. [Medium] Missing HSTS header
   WEB-HDR-001 · HTTP Security · Confirmed · escalated → WEB-HDR-001-CONFIRM
   Response from https://example.com does not include HSTS.
   Impact: Missing headers increase risk of clickjacking, XSS amplification, and downgrade attacks.
   Fix:    Set HSTS (and related browser security headers) at the edge.

   ↳ 2. [Info] Next: HTTP redirects to HTTPS
     WEB-HDR-001-CONFIRM · Escalation · Confirmed · from WEB-HDR-001
      Probed http://example.com/ → https://example.com/.
      Redirect exists, but HSTS is still missing (first-visit / MITM risk).

3. [Medium] Missing Content-Security-Policy header
   WEB-HDR-001 · HTTP Security · Confirmed · escalated → WEB-HDR-001-NEXT
   Response from https://example.com does not include Content-Security-Policy.

   ↳ 4. [Medium] Next: no CSP and no frame controls
     WEB-HDR-001-NEXT · Escalation · Confirmed · from WEB-HDR-001
      Neither CSP frame-ancestors nor X-Frame-Options is set.

5. [Info] server header discloses technology
   WEB-HDR-002 · HTTP Security · Confirmed
   Response includes `server: cloudflare`.

Expected surface (not scored as vulnerabilities)
------------------------------------------------------------------------
  · Website TLS certificate validation: TLS certificate is valid for this hostname.

========================================================================
Tip: use --json for machine-readable output.
```

On **Standard** / **Deep**, High and key Medium findings trigger **bounded escalation** — extra read-only probes that confirm impact (nested as `↳ Next:`). Quick skips escalation.

## Install

```bash
git clone https://github.com/ehsanhajian/dapptility.git
cd dapptility/scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Commands

| Command | What it scans |
|---|---|
| `dapptility-scan web <url>` | HTTP/TLS: headers, certificate, security.txt, robots.txt, … |
| `dapptility-scan rpc <url>` | Auto-detect RPC family |
| `dapptility-scan scan <url>` | EVM JSON-RPC |
| `dapptility-scan solana <url>` | Solana JSON-RPC |
| `dapptility-scan substrate <url>` | Substrate / Polkadot JSON-RPC |
| `dapptility-scan cosmos <url>` | Cosmos / Tendermint RPC |
| `dapptility-scan contract <addr> --rpc <url> [--chain <id>]` | EVM contract (code, proxies, bytecode, Sourcify) |
| `dapptility-scan profiles` | Profile budgets |
| `dapptility-scan rules [--module all]` | Rule catalog |

### Profiles

| Profile | Intent |
|---|---|
| `Quick` | Fast pass, no escalation |
| `Standard` | Default assessment + escalation |
| `Deep` | Larger budget, richer follow-ups |

Aliases: `Free`→`Quick`, `Outbound`→`Standard`, `Authorized-Full`→`Deep`.

### Output options

```bash
dapptility-scan web https://example.com                 # human report (default)
dapptility-scan web https://example.com --json --pretty # machine JSON
dapptility-scan web https://example.com --no-color
```

Exit code `2` = blocked/aborted (unsafe target, kill switch, unknown RPC family, `--block-providers`, …).

## More examples

```bash
# EVM RPC
dapptility-scan scan https://rpc.example.com --profile Standard

# Auto-detect Solana / Substrate / Cosmos
dapptility-scan rpc https://api.mainnet-beta.solana.com
dapptility-scan substrate https://rpc.polkadot.io
dapptility-scan cosmos https://rpc.cosmos.directory:443

# Contract (read-only)
dapptility-scan contract 0x… --rpc https://rpc.example.com --chain 1 --profile Standard
```

## Safety

- SSRF / private-IP / localhost / metadata blocking
- Per-profile request, RPS, and duration budgets
- Kill switch: create `/tmp/dapptility-scan-kill` or set `DAPPILITY_KILL_SWITCH`
- Escalation is confirmation-oriented — no exploit or funded-tx payloads
- EVM chain names from a bundled [Chainlist](https://chainid.network) snapshot

## Development

```bash
cd scanner
source .venv/bin/activate
pytest -q
```

Layout:

```
scanner/   engines + CLI (dapptility-scan)
```

## Authorized use

Only scan systems you own or have permission to assess. Unauthorized scanning may be illegal.

## License

Proprietary — all rights reserved unless otherwise stated.
