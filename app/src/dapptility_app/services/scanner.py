from __future__ import annotations

from dapptility_scanner.contract_engine import ContractScannerEngine
from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.profiles import normalize_profile_name
from dapptility_scanner.web_engine import WebScannerEngine


def run_scan_for_endpoint(
    url: str | None,
    profile: str,
    *,
    kind: str = "rpc",
    address: str | None = None,
    chain_id: int | None = None,
    abi_json: str | None = None,
    block_providers: bool = False,
):
    # Canonicalize so persisted scan.profile uses Quick/Standard/Deep
    profile_name = normalize_profile_name(profile).value

    if kind in {"web", "website"}:
        if not url:
            raise ValueError("Web scans require a URL")
        return WebScannerEngine(url, profile_name).run()
    if kind == "contract":
        if not address:
            raise ValueError("Contract scans require an address")
        if not url:
            raise ValueError("Contract scans require an RPC URL")
        return ContractScannerEngine(
            address,
            rpc_url=url,
            chain_id=chain_id,
            profile=profile_name,
            abi_json=abi_json,
        ).run()
    if not url:
        raise ValueError("RPC scans require a URL")
    return ScannerEngine(
        url,
        profile_name,
        block_providers=block_providers,
    ).run()
