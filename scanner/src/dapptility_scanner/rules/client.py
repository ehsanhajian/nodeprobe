from __future__ import annotations

import re

from dapptility_scanner.models import CheckKind, Confidence, ScanProfile, Severity
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

    # Heuristic: very old major lines often correlate with unpatched CVEs.
    _RISKY = (
        (re.compile(r"Geth/v1\.(9|10|11)\.", re.I), "Geth v1.9–v1.11 era"),
        (re.compile(r"Geth/v1\.12\.", re.I), "Geth v1.12 era"),
        (re.compile(r"Nethermind/v1\.(1[0-4])\.", re.I), "older Nethermind 1.x"),
        (re.compile(r"erigon/2\.", re.I), "Erigon 2.x line"),
    )

    def run(self, client, context):
        result = client.call("web3_clientVersion")
        if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
            return []
        version = str(result)
        context["client_version"] = version

        risk_note = None
        for pattern, label in self._RISKY:
            if pattern.search(version):
                risk_note = label
                break

        if risk_note and client.limits.name == ScanProfile.DEEP:
            return [
                self.finding(
                    title="Client version may be outdated",
                    severity=Severity.MEDIUM,
                    score_impact=10,
                    evidence={"client_version": version, "risk_note": risk_note},
                    description=(
                        f"Endpoint discloses client version `{version}` "
                        f"({risk_note}). Confirm patch level against current releases."
                    ),
                )
            ]

        return [
            self.finding(
                evidence={"client_version": version, "risk_note": risk_note},
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


class RpcModulesRule(Rule):
    """Deep-only: list enabled API modules when the node exposes rpc_modules."""

    meta = RuleMeta(
        rule_id="EVM-CLIENT-003",
        title="Enabled RPC modules enumeration",
        description="rpc_modules lists enabled API namespaces on some clients.",
        category="Client Exposure",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Module lists reveal which privileged APIs are compiled/enabled.",
        remediation="Disable rpc_modules on public listeners; restrict namespaces at the edge.",
        score_impact=8,
        allowed_profiles=(ScanProfile.DEEP,),
    )

    def run(self, client, context):
        available, detail = client.method_available("rpc_modules")
        if not available:
            return []
        modules = None
        if isinstance(detail, dict) and "__rpc_error__" not in detail and "__http_error__" not in detail:
            modules = detail
        privileged = []
        if isinstance(modules, dict):
            for name in modules:
                key = str(name).lower()
                if key in {"admin", "debug", "personal", "miner", "engine", "txpool", "clique"}:
                    privileged.append(key)
            context["rpc_modules"] = modules
        return [
            self.finding(
                evidence={"modules": modules, "privileged": privileged},
                description=(
                    "rpc_modules is available"
                    + (
                        f" and lists privileged modules: {', '.join(sorted(privileged))}"
                        if privileged
                        else "."
                    )
                ),
                severity=Severity.HIGH if privileged else Severity.MEDIUM,
                score_impact=15 if privileged else 8,
            )
        ]
