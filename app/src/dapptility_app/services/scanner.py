from __future__ import annotations

from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.models import ScanProfile


def run_scan_for_endpoint(url: str, profile: str):
    block_providers = profile == ScanProfile.OUTBOUND.value
    return ScannerEngine(
        url,
        profile,
        block_providers=block_providers,
    ).run()
