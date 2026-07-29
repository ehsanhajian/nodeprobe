from __future__ import annotations

from dapptility_scanner.models import CheckKind, Confidence, Severity
from dapptility_scanner.rules.base import Rule, RuleMeta


# Presence-only probes — no expensive payloads on Free/Outbound.
NAMESPACE_PROBES: list[tuple[str, str, Severity, int, str]] = [
    (
        "EVM-NS-DEBUG",
        "debug_traceBlockByNumber",
        Severity.CRITICAL,
        35,
        "debug_*",
    ),
    (
        "EVM-NS-TRACE",
        "trace_block",
        Severity.HIGH,
        25,
        "trace_*",
    ),
    (
        "EVM-NS-ADMIN",
        "admin_nodeInfo",
        Severity.CRITICAL,
        40,
        "admin_*",
    ),
    (
        "EVM-NS-PERSONAL",
        "personal_listAccounts",
        Severity.CRITICAL,
        40,
        "personal_*",
    ),
    (
        "EVM-NS-TXPOOL",
        "txpool_content",
        Severity.MEDIUM,
        12,
        "txpool_*",
    ),
    (
        "EVM-NS-ENGINE",
        "engine_getClientVersionV1",
        Severity.CRITICAL,
        40,
        "engine_*",
    ),
]


class NamespaceExposureRule(Rule):
    """Factory-built presence probes for privileged namespaces."""

    def __init__(
        self,
        rule_id: str,
        method: str,
        severity: Severity,
        score_impact: int,
        namespace: str,
    ):
        self.method = method
        self.namespace = namespace
        self.meta = RuleMeta(
            rule_id=rule_id,
            title=f"Exposed {namespace} namespace",
            description=(
                f"Presence probe for {method}. Does not execute expensive payloads "
                "on Free or Outbound profiles."
            ),
            category="RPC Method Exposure",
            severity=severity,
            confidence=Confidence.CONFIRMED,
            kind=CheckKind.FINDING,
            impact=(
                f"Exposed {namespace} methods can leak sensitive node data or enable abuse."
            ),
            remediation=(
                f"Disable or authenticate the {namespace} namespace on public RPC endpoints "
                "(Nginx/HAProxy/Envoy method allowlists)."
            ),
            references=[
                "https://geth.ethereum.org/docs/interacting-with-geth/rpc",
            ],
            score_impact=score_impact,
        )

    def run(self, client, context):
        # Presence only: empty/safe params. Never send heavy debug payloads here.
        params: list = []
        if self.method == "debug_traceBlockByNumber":
            # Still a presence probe; many nodes reject before heavy work if disabled.
            # Use "latest" with empty tracer config only on Authorized-Full if ever expanded.
            # For Free/Outbound we call with empty params which typically returns method error
            # without expensive execution when disabled, or a param error when enabled.
            params = []
        available, detail = client.method_available(self.method, params)
        if not available:
            return []
        return [
            self.finding(
                evidence={
                    "method": self.method,
                    "namespace": self.namespace,
                    "probe_detail": detail if not isinstance(detail, (bytes, bytearray)) else str(detail),
                    "expensive_payload_sent": False,
                },
                description=(
                    f"Method {self.method} appears available on the public endpoint "
                    f"({self.namespace} namespace)."
                ),
            )
        ]


class ExpectedSurfaceRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-SURFACE-001",
        title="Expected public RPC methods",
        description="Common public read/send methods are expected on public RPCs.",
        category="Expected Surface",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.EXPECTED_SURFACE,
        score_impact=0,
    )

    METHODS = (
        "eth_blockNumber",
        "eth_chainId",
        "eth_getBalance",
        "eth_call",
        "eth_sendRawTransaction",
    )

    def run(self, client, context):
        present = []
        for method in self.METHODS:
            if method in {"eth_blockNumber", "eth_chainId"} and context.get("chain_id") is not None:
                present.append(method)
                continue
            params: list = []
            if method == "eth_getBalance":
                params = ["0x0000000000000000000000000000000000000000", "latest"]
            elif method == "eth_call":
                params = [
                    {
                        "to": "0x0000000000000000000000000000000000000000",
                        "data": "0x",
                    },
                    "latest",
                ]
            elif method == "eth_sendRawTransaction":
                # Presence via invalid short payload — should fail with param/validation error
                # if method exists, or method-not-found if disabled.
                params = ["0x"]
            available, _ = client.method_available(method, params)
            if available:
                present.append(method)
        if not present:
            return []
        return [
            self.finding(
                evidence={"methods": present},
                description=(
                    "The following methods are present and treated as expected public "
                    f"surface (not scored as vulnerabilities): {', '.join(present)}"
                ),
            )
        ]


def namespace_rules() -> list[Rule]:
    return [
        NamespaceExposureRule(rule_id, method, severity, score, ns)
        for rule_id, method, severity, score, ns in NAMESPACE_PROBES
    ]
