from __future__ import annotations

import argparse
import json
import sys

from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.profiles import PROFILES
from dapptility_scanner.rules import all_rules
from dapptility_scanner.rules.web import web_rules
from dapptility_scanner.web_engine import WebScannerEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dapptility-scan",
        description="Dapptility personal scanner — web, EVM JSON-RPC, and contracts",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an HTTP JSON-RPC endpoint")
    scan.add_argument("url", help="HTTP(S) JSON-RPC endpoint URL")
    scan.add_argument(
        "--profile",
        default="Free",
        help="Scan profile: Free | Outbound | Authorized-Full (default: Free)",
    )
    scan.add_argument(
        "--block-providers",
        action="store_true",
        help="Block known third-party provider hostnames (always on for Outbound)",
    )
    scan.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    web = sub.add_parser("web", help="Scan a website (HTTP/TLS surface)")
    web.add_argument("url", help="HTTP(S) website URL")
    web.add_argument(
        "--profile",
        default="Free",
        help="Scan profile: Free | Outbound | Authorized-Full (default: Free)",
    )
    web.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    sub.add_parser("profiles", help="List scan profiles and budgets")
    rules = sub.add_parser("rules", help="List registered rules")
    rules.add_argument(
        "--module",
        choices=("rpc", "web", "all"),
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
        ruleset = []
        if args.module in {"rpc", "all"}:
            ruleset.extend(all_rules())
        if args.module in {"web", "all"}:
            ruleset.extend(web_rules())
        payload = [
            {
                "rule_id": r.meta.rule_id,
                "title": r.meta.title,
                "category": r.meta.category,
                "severity": r.meta.severity.value,
                "kind": r.meta.kind.value,
                "profiles": [p.value for p in r.meta.allowed_profiles],
            }
            for r in ruleset
        ]
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

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
