from __future__ import annotations

from dapptility_scanner.models import CheckKind, Confidence, Severity
from dapptility_scanner.rules.base import Rule, RuleMeta


class ClientVersionRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-CLIENT-001",
        title="Client version exposure",
        description="web3_clientVersion reveals client name and version.",
        category="Client Exposure",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Exact client versions help attackers target known CVEs.",
        remediation=(
            "Consider masking or normalizing client version responses at the "
            "reverse proxy for public endpoints."
        ),
        score_impact=5,
    )

    def run(self, client, context):
        result = client.call("web3_clientVersion")
        if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
            return []
        version = str(result)
        context["client_version"] = version
        # Always record as a low finding when exact version string is returned
        return [
            self.finding(
                evidence={"client_version": version},
                description=f"Endpoint discloses client version: {version}",
            )
        ]


class ServerHeaderRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-CLIENT-002",
        title="Server header disclosure",
        description="HTTP Server header reveals backend or proxy software.",
        category="Client Exposure",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.INFO,
        impact="Server banners aid fingerprinting.",
        remediation="Remove or generalize the Server response header.",
        score_impact=0,
    )

    def run(self, client, context):
        # Ensure at least one request has been made
        if not client.last_headers:
            client.call("eth_chainId")
        server = client.last_headers.get("server")
        if not server:
            return []
        context["server_header"] = server
        # Version-like tokens elevate slightly
        severity = Severity.LOW if any(ch.isdigit() for ch in server) else Severity.INFO
        kind = CheckKind.FINDING if severity == Severity.LOW else CheckKind.INFO
        return [
            self.finding(
                severity=severity,
                kind=kind,
                score_impact=3 if severity == Severity.LOW else 0,
                evidence={"server": server},
                description=f"Server header discloses: {server}",
            )
        ]


class ContentTypeRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-HTTP-001",
        title="JSON-RPC Content-Type",
        description="Responses should use an application/json Content-Type.",
        category="HTTP Security",
        severity=Severity.LOW,
        confidence=Confidence.LIKELY,
        kind=CheckKind.FINDING,
        impact="Unexpected content types can indicate proxy misconfiguration.",
        remediation="Configure the RPC gateway to return application/json.",
        score_impact=3,
    )

    def run(self, client, context):
        if not client.last_content_type:
            return []
        ct = client.last_content_type.lower()
        if "application/json" in ct or "json" in ct:
            return [
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    score_impact=0,
                    evidence={"content_type": client.last_content_type},
                    description="Response Content-Type is JSON.",
                )
            ]
        return [
            self.finding(
                evidence={"content_type": client.last_content_type},
                description=f"Unexpected Content-Type: {client.last_content_type}",
            )
        ]
