from __future__ import annotations

from dapptility_scanner.contract_engine import ContractScannerEngine
from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.models import ScanProfile
from dapptility_scanner.web_engine import WebScannerEngine


def run_scan_for_endpoint(
    url: str | None,
    profile: str,
    *,
    kind: str = "rpc",
    address: str | None = None,
    chain_id: int | None = None,
    abi_json: str | None = None,
):
    if kind in {"web", "website"}:
        if not url:
            raise ValueError("Web scans require a URL")
        return WebScannerEngine(url, profile).run()
    if kind == "contract":
        if not address:
            raise ValueError("Contract scans require an address")
        if not url:
            raise ValueError("Contract scans require an RPC URL")
        return ContractScannerEngine(
            address,
            rpc_url=url,
            chain_id=chain_id,
            profile=profile,
            abi_json=abi_json,
        ).run()
    if not url:
        raise ValueError("RPC scans require a URL")
    block_providers = profile == ScanProfile.OUTBOUND.value
    return ScannerEngine(
        url,
        profile,
        block_providers=block_providers,
    ).run()
