from __future__ import annotations

import argparse
import json
import sys

from dapptility_scanner.contract_engine import ContractScannerEngine
from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.profiles import PROFILES
from dapptility_scanner.rules import all_rules
from dapptility_scanner.rules.web import web_rules
from dapptility_scanner.web_engine import WebScannerEngine

CONTRACT_RULE_CATALOG = [
    {"rule_id": "SC-IDENT-001", "title": "RPC chain ID mismatch", "category": "Identity"},
    {"rule_id": "SC-IDENT-002", "title": "Chain outside maintained support list", "category": "Identity"},
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
    "(aliases: Free→Quick, Outbound→Standard, Authorized-Full→Deep; default: Quick)"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dapptility-scan",
        description="Dapptility personal scanner — web, EVM JSON-RPC, and contracts",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an HTTP JSON-RPC endpoint")
    scan.add_argument("url", help="HTTP(S) JSON-RPC endpoint URL")
    scan.add_argument("--profile", default="Quick", help=_PROFILE_HELP)
    scan.add_argument(
        "--block-providers",
        action="store_true",
        help="Block known third-party provider hostnames (Alchemy, Infura, …)",
    )
    scan.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    web = sub.add_parser("web", help="Scan a website (HTTP/TLS surface)")
    web.add_argument("url", help="HTTP(S) website URL")
    web.add_argument("--profile", default="Quick", help=_PROFILE_HELP)
    web.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    contract = sub.add_parser("contract", help="Scan a smart contract via read-only RPC")
    contract.add_argument("address", help="Contract address (0x…)")
    contract.add_argument("--rpc", required=True, help="HTTP(S) JSON-RPC URL for the chain")
    contract.add_argument("--chain", type=int, default=None, help="Expected chain ID")
    contract.add_argument("--profile", default="Quick", help=_PROFILE_HELP)
    contract.add_argument(
        "--no-sourcify",
        action="store_true",
        help="Skip Sourcify verification lookup",
    )
    contract.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    sub.add_parser("profiles", help="List scan profiles and budgets")
    rules = sub.add_parser("rules", help="List registered rules")
    rules.add_argument(
        "--module",
        choices=("rpc", "web", "contract", "all"),
        default="all",
        help="Rule module to list (default: all)",
    )

    return parser


def _print_result(result, *, pretty: bool) -> int:
    print(json.dumps(result.to_dict(), indent=2 if pretty else None))
    if result.aborted and result.abort_reason in {
        "unsafe_target",
        "unsupported_chain",
        "third_party_provider",
        "kill_switch",
        "invalid_address",
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
        payload = []
        if args.module in {"rpc", "all"}:
            payload.extend(
                {
                    "rule_id": r.meta.rule_id,
                    "title": r.meta.title,
                    "category": r.meta.category,
                    "severity": r.meta.severity.value,
                    "kind": r.meta.kind.value,
                    "profiles": [p.value for p in r.meta.allowed_profiles],
                }
                for r in all_rules()
            )
        if args.module in {"web", "all"}:
            payload.extend(
                {
                    "rule_id": r.meta.rule_id,
                    "title": r.meta.title,
                    "category": r.meta.category,
                    "severity": r.meta.severity.value,
                    "kind": r.meta.kind.value,
                    "profiles": [p.value for p in r.meta.allowed_profiles],
                }
                for r in web_rules()
            )
        if args.module in {"contract", "all"}:
            payload.extend(
                {
                    **item,
                    "severity": "varies",
                    "kind": "finding",
                    "profiles": ["Quick", "Standard", "Deep"],
                }
                for item in CONTRACT_RULE_CATALOG
            )
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "scan":
        result = ScannerEngine(
            args.url,
            args.profile,
            block_providers=args.block_providers,
        ).run()
        return _print_result(result, pretty=args.pretty)

    if args.command == "web":
        result = WebScannerEngine(args.url, args.profile).run()
        return _print_result(result, pretty=args.pretty)

    if args.command == "contract":
        result = ContractScannerEngine(
            args.address,
            rpc_url=args.rpc,
            chain_id=args.chain,
            profile=args.profile,
            fetch_verification=not args.no_sourcify,
        ).run()
        return _print_result(result, pretty=args.pretty)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
