"""Test helpers that build scanner ScanResult objects without network."""

from __future__ import annotations

from datetime import datetime, timezone

from dapptility_scanner import __version__
from dapptility_scanner.models import (
    CheckKind,
    Confidence,
    Finding,
    ScanProfile,
    ScanResult,
    Severity,
)


def make_scan_result(url: str, profile: str) -> ScanResult:
    now = datetime.now(timezone.utc).isoformat()
    finding = Finding(
        rule_id="EVM-NS-ADMIN",
        title="Exposed admin_* namespace",
        category="RPC Method Exposure",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        description="admin_nodeInfo appears available.",
        evidence={"method": "admin_nodeInfo"},
        remediation="Disable admin namespace on public RPC.",
        score_impact=40,
    )
    surface = Finding(
        rule_id="EVM-IDENT-001",
        title="Chain ID resolved",
        category="Network Identity",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.EXPECTED_SURFACE,
        description="Chain ID 1 mapped to Ethereum Mainnet.",
        evidence={"chain_id": 1},
    )
    return ScanResult(
        scanner_version=__version__,
        profile=ScanProfile(profile),
        endpoint=url,
        started_at=now,
        finished_at=now,
        duration_ms=1200,
        requests_made=8,
        chain_id=1,
        network_name="Ethereum Mainnet",
        client_version="Geth/v1.13.0",
        score=35,
        findings=[finding],
        expected_surface=[surface],
        errors=[],
        aborted=False,
        abort_reason=None,
        provider=None,
    )
