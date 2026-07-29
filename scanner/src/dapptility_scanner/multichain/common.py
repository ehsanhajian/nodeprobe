"""Shared helpers for non-EVM JSON-RPC / Tendermint scanners."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from dapptility_scanner.models import CheckKind, Confidence, Finding, Severity


def is_rpc_failure(result: Any) -> bool:
    return isinstance(result, dict) and (
        "__rpc_error__" in result or "__http_error__" in result
    )


def finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    kind: CheckKind,
    description: str,
    confidence: Confidence = Confidence.CONFIRMED,
    evidence: dict[str, Any] | None = None,
    impact: str = "",
    remediation: str = "",
    references: list[str] | None = None,
    score_impact: int = 0,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        kind=kind,
        description=description,
        evidence=evidence or {},
        impact=impact,
        remediation=remediation,
        references=references or [],
        score_impact=score_impact,
    )


def probe_tls(url: str) -> list[Finding]:
    """Lightweight TLS check shared by multichain RPC scanners."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [
            finding(
                rule_id="MC-TLS-001",
                title="RPC endpoint not using HTTPS",
                category="TLS Security",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description="Endpoint is not served over HTTPS.",
                evidence={"scheme": parsed.scheme},
                impact="Cleartext RPC exposes traffic to interception.",
                remediation="Serve the RPC over HTTPS with a valid certificate.",
                score_impact=10,
            )
        ]
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        return []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return [
            finding(
                rule_id="MC-TLS-001",
                title="TLS certificate validation failed",
                category="TLS Security",
                severity=Severity.HIGH,
                kind=CheckKind.FINDING,
                description=f"TLS certificate verification failed: {exc}",
                evidence={"error": str(exc)},
                impact="Invalid TLS weakens transport integrity for RPC clients.",
                remediation="Issue a valid certificate covering the RPC hostname.",
                score_impact=20,
            )
        ]
    except OSError as exc:
        return [
            finding(
                rule_id="MC-TLS-001",
                title="TLS probe failed",
                category="TLS Security",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                confidence=Confidence.LIKELY,
                description=f"TLS probe failed: {exc}",
                evidence={"error": str(exc)},
                score_impact=10,
            )
        ]

    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expiry - datetime.now(timezone.utc)).days
        if days_left < 0:
            return [
                finding(
                    rule_id="MC-TLS-001",
                    title="TLS certificate expired",
                    category="TLS Security",
                    severity=Severity.HIGH,
                    kind=CheckKind.FINDING,
                    description="TLS certificate has expired.",
                    evidence={"not_after": not_after, "days_left": days_left},
                    score_impact=20,
                )
            ]
        if days_left < 14:
            return [
                finding(
                    rule_id="MC-TLS-001",
                    title="TLS certificate expiring soon",
                    category="TLS Security",
                    severity=Severity.MEDIUM,
                    kind=CheckKind.FINDING,
                    description=f"TLS certificate expires in {days_left} days.",
                    evidence={"not_after": not_after, "days_left": days_left},
                    score_impact=8,
                )
            ]
    return [
        finding(
            rule_id="MC-TLS-001",
            title="TLS certificate validation",
            category="TLS Security",
            severity=Severity.INFO,
            kind=CheckKind.EXPECTED_SURFACE,
            description="TLS certificate is valid for this hostname.",
            evidence={"not_after": not_after, "days_left": days_left},
        )
    ]


def split_findings(items: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    findings: list[Finding] = []
    expected: list[Finding] = []
    for item in items:
        if item.kind == CheckKind.EXPECTED_SURFACE:
            expected.append(item)
        else:
            findings.append(item)
    return findings, expected
