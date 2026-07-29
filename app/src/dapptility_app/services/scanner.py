from __future__ import annotations

from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.models import ScanProfile
from dapptility_scanner.web_engine import WebScannerEngine


def run_scan_for_endpoint(url: str, profile: str, *, kind: str = "rpc"):
    if kind == "web" or kind == "website":
        return WebScannerEngine(url, profile).run()
    if kind == "contract":
        raise ValueError("Contract scanner is not implemented yet")
    block_providers = profile == ScanProfile.OUTBOUND.value
    return ScannerEngine(
        url,
        profile,
        block_providers=block_providers,
    ).run()
