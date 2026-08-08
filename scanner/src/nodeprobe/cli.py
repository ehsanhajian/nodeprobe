from __future__ import annotations

import argparse
import json
import sys

from nodeprobe.contract_engine import ContractScannerEngine
from nodeprobe.engine import ScannerEngine
from nodeprobe.multichain import MultichainRpcEngine
from nodeprobe.multichain.aptos_engine import APTOS_RULE_CATALOG, AptosScannerEngine
from nodeprobe.multichain.cosmos_engine import COSMOS_RULE_CATALOG, CosmosScannerEngine
from nodeprobe.multichain.solana_engine import SOLANA_RULE_CATALOG, SolanaScannerEngine
from nodeprobe.multichain.substrate_engine import (
    SUBSTRATE_RULE_CATALOG,
    SubstrateScannerEngine,
)
from nodeprobe.multichain.sui_engine import SUI_RULE_CATALOG, SuiScannerEngine
from nodeprobe.profiles import PROFILES
from nodeprobe.report import format_html_report, format_human_report
from nodeprobe.rules import all_rules
from nodeprobe.rules.web import web_rules
from nodeprobe.web_engine import WebScannerEngine

CONTRACT_RULE_CATALOG = [
    {"rule_id": "SC-IDENT-001", "title": "RPC chain ID mismatch", "category": "Identity"},
    {"rule_id": "SC-IDENT-002", "title": "Chain not in local name registry", "category": "Identity"},
    {"rule_id": "SC-CODE-001", "title": "Contract code presence", "category": "Code"},
    {"rule_id": "SC-PROXY-001", "title": "Proxy pattern detection", "category": "Proxy"},
    {"rule_id": "SC-BYTE-001", "title": "SELFDESTRUCT presence", "category": "Bytecode"},
    {"rule_id": "SC-BYTE-002", "title": "DELEGATECALL presence", "category": "Bytecode"},
    {"rule_id": "SC-SRC-001", "title": "Sourcify verification", "category": "Source"},
    {"rule_id": "SC-IFACE-001", "title": "Interface hints", "category": "Interfaces"},
    {"rule_id": "SC-IFACE-002", "title": "Ownable-style ownership surface", "category": "Access Control"},
]


_PROFILE_HELP = (
    "Scan profile: Quick | Standard | Deep "
    "(aliases: Free→Quick, Outbound→Standard, Authorized-Full→Deep; default: Standard)"
)
_FAMILY_HELP = (
    "RPC family: auto | evm | solana | substrate | cosmos | aptos | sui "
    "(default: auto)"
)


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a human-readable report",
    )
    fmt.add_argument(
        "--html",
        action="store_true",
        help="Emit a self-contained HTML report",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="With --json: indent JSON. Without --json: human report (default).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Write the report to PATH instead of stdout",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Human report: include evidence and full detail for Low/Info findings",
    )
    color = parser.add_mutually_exclusive_group()
    color.add_argument(
        "--color",
        action="store_true",
        help="Force ANSI colors in the human report",
    )
    color.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in the human report",
    )


def _add_rpc_flags(parser: argparse.ArgumentParser, *, include_family: bool = False) -> None:
    parser.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    if include_family:
        parser.add_argument("--family", default="auto", help=_FAMILY_HELP)
    parser.add_argument(
        "--block-providers",
        action="store_true",
        help="Block known third-party provider hostnames (EVM only)",
    )
    _add_output_flags(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nodeprobe",
        description=(
            "Nodeprobe — website, multi-chain RPC, and EVM contract scanner"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rpc = sub.add_parser(
        "rpc",
        help="Scan an RPC endpoint (auto-detect family, or set --family)",
    )
    rpc.add_argument("url", help="HTTP(S) RPC endpoint URL")
    _add_rpc_flags(rpc, include_family=True)

    scan = sub.add_parser("scan", help="Scan an EVM JSON-RPC endpoint (alias of rpc --family evm)")
    scan.add_argument("url", help="HTTP(S) JSON-RPC endpoint URL")
    _add_rpc_flags(scan)

    solana = sub.add_parser("solana", help="Scan a Solana JSON-RPC endpoint")
    solana.add_argument("url", help="HTTP(S) Solana RPC URL")
    solana.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    _add_output_flags(solana)

    substrate = sub.add_parser(
        "substrate",
        help="Scan a Substrate / Polkadot JSON-RPC endpoint",
    )
    substrate.add_argument("url", help="HTTP(S) Substrate RPC URL")
    substrate.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    _add_output_flags(substrate)

    cosmos = sub.add_parser("cosmos", help="Scan a Cosmos / Tendermint RPC endpoint")
    cosmos.add_argument("url", help="HTTP(S) Tendermint / Cosmos RPC URL")
    cosmos.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    _add_output_flags(cosmos)

    aptos = sub.add_parser("aptos", help="Scan an Aptos fullnode REST API (/v1)")
    aptos.add_argument("url", help="HTTP(S) Aptos fullnode URL (with or without /v1)")
    aptos.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    _add_output_flags(aptos)

    sui = sub.add_parser("sui", help="Scan a Sui GraphQL RPC endpoint")
    sui.add_argument("url", help="HTTP(S) Sui GraphQL RPC URL")
    sui.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    _add_output_flags(sui)

    web = sub.add_parser("web", help="Scan a website (HTTP/TLS surface)")
    web.add_argument("url", help="HTTP(S) website URL")
    web.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    _add_output_flags(web)

    contract = sub.add_parser("contract", help="Scan an EVM smart contract via read-only RPC")
    contract.add_argument("address", help="Contract address (0x…)")
    contract.add_argument("--rpc", required=True, help="HTTP(S) JSON-RPC URL for the chain")
    contract.add_argument("--chain", type=int, default=None, help="Expected chain ID")
    contract.add_argument("--profile", default="Standard", help=_PROFILE_HELP)
    contract.add_argument(
        "--no-sourcify",
        action="store_true",
        help="Skip Sourcify verification lookup",
    )
    _add_output_flags(contract)

    sub.add_parser("profiles", help="List scan profiles and budgets")
    rules = sub.add_parser("rules", help="List registered rules")
    rules.add_argument(
        "--module",
        choices=(
            "rpc",
            "evm",
            "web",
            "contract",
            "solana",
            "substrate",
            "cosmos",
            "aptos",
            "sui",
            "all",
        ),
        default="all",
        help="Rule module to list (default: all)",
    )

    return parser


def _color_flag(args: argparse.Namespace) -> bool | None:
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "color", False):
        return True
    return None


def _print_result(
    result,
    *,
    as_json: bool,
    as_html: bool,
    pretty: bool,
    color: bool | None,
    verbose: bool = False,
    output: str | None = None,
) -> int:
    if as_json:
        payload = json.dumps(result.to_dict(), indent=2 if pretty else None)
    elif as_html:
        payload = format_html_report(result)
    else:
        payload = format_human_report(result, color=color, verbose=verbose)

    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(payload if payload.endswith("\n") else payload + "\n")
        print(f"Wrote report to {output}", file=sys.stderr)
    else:
        print(payload, end="" if payload.endswith("\n") else "\n")

    if result.aborted and result.abort_reason in {
        "unsafe_target",
        "third_party_provider",
        "kill_switch",
        "invalid_address",
        "unknown_family",
    }:
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "profiles":
        payload = {
            name.value: {
                "max_requests": limits.max_requests,
                "max_rps": limits.max_rps,
                "max_duration_seconds": limits.max_duration_seconds,
                "allow_expensive_namespace_calls": limits.allow_expensive_namespace_calls,
                "allow_rate_limit_stress": limits.allow_rate_limit_stress,
            }
            for name, limits in PROFILES.items()
        }
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "rules":
        module = args.module
        payload = []
        if module in {"rpc", "evm", "all"}:
            payload.extend(
                {
                    "rule_id": r.meta.rule_id,
                    "title": r.meta.title,
                    "category": r.meta.category,
                    "severity": r.meta.severity.value,
                    "kind": r.meta.kind.value,
                    "profiles": [p.value for p in r.meta.allowed_profiles],
                    "module": "evm",
                }
                for r in all_rules()
            )
        if module in {"web", "all"}:
            payload.extend(
                {
                    "rule_id": r.meta.rule_id,
                    "title": r.meta.title,
                    "category": r.meta.category,
                    "severity": r.meta.severity.value,
                    "kind": r.meta.kind.value,
                    "profiles": [p.value for p in r.meta.allowed_profiles],
                    "module": "web",
                }
                for r in web_rules()
            )
        if module in {"contract", "all"}:
            payload.extend(
                {
                    **item,
                    "severity": "varies",
                    "kind": "finding",
                    "profiles": ["Quick", "Standard", "Deep"],
                    "module": "contract",
                }
                for item in CONTRACT_RULE_CATALOG
            )
        if module in {"solana", "rpc", "all"}:
            payload.extend(
                {**item, "severity": "varies", "kind": "finding", "profiles": ["Quick", "Standard", "Deep"], "module": "solana"}
                for item in SOLANA_RULE_CATALOG
            )
        if module in {"substrate", "rpc", "all"}:
            payload.extend(
                {**item, "severity": "varies", "kind": "finding", "profiles": ["Quick", "Standard", "Deep"], "module": "substrate"}
                for item in SUBSTRATE_RULE_CATALOG
            )
        if module in {"cosmos", "rpc", "all"}:
            payload.extend(
                {**item, "severity": "varies", "kind": "finding", "profiles": ["Quick", "Standard", "Deep"], "module": "cosmos"}
                for item in COSMOS_RULE_CATALOG
            )
        if module in {"aptos", "rpc", "all"}:
            payload.extend(
                {
                    **item,
                    "severity": "varies",
                    "kind": "finding",
                    "profiles": ["Quick", "Standard", "Deep"],
                    "module": "aptos",
                }
                for item in APTOS_RULE_CATALOG
            )
        if module in {"sui", "rpc", "all"}:
            payload.extend(
                {
                    **item,
                    "severity": "varies",
                    "kind": "finding",
                    "profiles": ["Quick", "Standard", "Deep"],
                    "module": "sui",
                }
                for item in SUI_RULE_CATALOG
            )
        print(json.dumps(payload, indent=2))
        return 0

    color = _color_flag(args)
    out_kwargs = {
        "as_json": bool(getattr(args, "json", False)),
        "as_html": bool(getattr(args, "html", False)),
        "pretty": bool(getattr(args, "pretty", False)),
        "color": color,
        "verbose": bool(getattr(args, "verbose", False)),
        "output": getattr(args, "output", None),
    }

    if args.command == "rpc":
        result = MultichainRpcEngine(
            args.url,
            args.profile,
            family=args.family,
            block_providers=args.block_providers,
        ).run()
        return _print_result(result, **out_kwargs)

    if args.command == "scan":
        result = ScannerEngine(
            args.url,
            args.profile,
            block_providers=args.block_providers,
        ).run()
        return _print_result(result, **out_kwargs)

    if args.command == "solana":
        result = SolanaScannerEngine(args.url, args.profile).run()
        return _print_result(result, **out_kwargs)

    if args.command == "substrate":
        result = SubstrateScannerEngine(args.url, args.profile).run()
        return _print_result(result, **out_kwargs)

    if args.command == "cosmos":
        result = CosmosScannerEngine(args.url, args.profile).run()
        return _print_result(result, **out_kwargs)

    if args.command == "aptos":
        result = AptosScannerEngine(args.url, args.profile).run()
        return _print_result(result, **out_kwargs)

    if args.command == "sui":
        result = SuiScannerEngine(args.url, args.profile).run()
        return _print_result(result, **out_kwargs)

    if args.command == "web":
        result = WebScannerEngine(args.url, args.profile).run()
        return _print_result(result, **out_kwargs)

    if args.command == "contract":
        result = ContractScannerEngine(
            args.address,
            rpc_url=args.rpc,
            chain_id=args.chain,
            profile=args.profile,
            fetch_verification=not args.no_sourcify,
        ).run()
        return _print_result(result, **out_kwargs)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
