from __future__ import annotations

from dapptility_scanner.models import CheckKind, Confidence, ScanProfile, Severity
from dapptility_scanner.providers import detect_provider
from dapptility_scanner.rules.base import Rule, RuleMeta


# Presence-only probes — no expensive payloads on Quick/Standard.
# Extra Deep methods are gated in NamespaceExposureRule / DeepConfirmRule.
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
    (
        "EVM-NS-MINER",
        "miner_start",
        Severity.HIGH,
        22,
        "miner_*",
    ),
    (
        "EVM-NS-CLIQUE",
        "clique_getSigners",
        Severity.MEDIUM,
        10,
        "clique_*",
    ),
    (
        "EVM-NS-ACCOUNTS",
        "eth_accounts",
        Severity.HIGH,
        20,
        "eth_accounts",
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
                "on Quick or Standard profiles."
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
        params: list = []
        available, detail = client.method_available(self.method, params)
        if not available:
            return []

        evidence = {
            "method": self.method,
            "namespace": self.namespace,
            "probe_detail": detail if not isinstance(detail, (bytes, bytearray)) else str(detail),
            "expensive_payload_sent": False,
            "profile": client.limits.name.value,
        }

        # Deep: cheap confirmation calls when expensive namespace work is allowed.
        # Still avoid full block traces (DoS risk).
        if (
            client.limits.allow_expensive_namespace_calls
            and self.method == "debug_traceBlockByNumber"
        ):
            confirm_ok, confirm_detail = client.method_available("debug_memStats")
            evidence["deep_confirm_method"] = "debug_memStats"
            evidence["deep_confirm_available"] = confirm_ok
            evidence["deep_confirm_detail"] = (
                confirm_detail
                if not isinstance(confirm_detail, (bytes, bytearray))
                else str(confirm_detail)
            )
            if confirm_ok:
                evidence["expensive_payload_sent"] = False  # memStats is cheap
                return [
                    self.finding(
                        title="Exposed debug_* namespace (Deep-confirmed)",
                        evidence=evidence,
                        description=(
                            f"Method {self.method} appears available and debug_memStats "
                            "also responds — debug API is enabled on this listener."
                        ),
                        score_impact=self.meta.score_impact + 5,
                    )
                ]

        return [
            self.finding(
                evidence=evidence,
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
        description=(
            "Common public read/send methods are expected on public RPCs and are "
            "labeled expected_surface (not scored as vulnerabilities)."
        ),
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
        "eth_gasPrice",
        "net_version",
    )

    def run(self, client, context):
        present = []
        for method in self.METHODS:
            if method in {"eth_blockNumber", "eth_chainId"} and context.get("chain_id") is not None:
                present.append(method)
                continue
            if method == "net_version" and context.get("network_name") is not None:
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
                params = ["0x"]
            available, _ = client.method_available(method, params)
            if available:
                present.append(method)
        if not present:
            return []
        return [
            self.finding(
                evidence={"methods": present, "label": "expected_surface"},
                description=(
                    "Expected-surface (not a vulnerability): public read/send methods present — "
                    f"{', '.join(present)}. Privileged namespaces are scored separately as findings."
                ),
            )
        ]


class ProviderInformationalRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-PROV-001",
        title="Third-party RPC provider detected",
        description="Hostname matches a known hosted RPC provider.",
        category="Provider",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.INFO,
        impact="Findings reflect provider-hosted infrastructure, not project-owned RPC stacks.",
        remediation="Prefer scanning project-owned RPC domains when assessing your own stack.",
        score_impact=0,
    )

    def run(self, client, context):
        match = detect_provider(client.target.original_url)
        if not match:
            return []
        context["provider"] = match.provider
        return [
            self.finding(
                evidence={
                    "provider": match.provider,
                    "reason": match.reason,
                    "blocked": False,
                },
                description=(
                    f"Endpoint appears hosted by {match.provider}. "
                    "Treated as informational unless --block-providers is set."
                ),
            )
        ]


class SoftRateLimitRule(Rule):
    """Deep-only light burst to observe 429 / rate-limit headers."""

    meta = RuleMeta(
        rule_id="EVM-RATE-001",
        title="Rate-limit behavior observation",
        description="Light request burst to observe HTTP 429 or rate-limit headers.",
        category="Availability",
        severity=Severity.INFO,
        confidence=Confidence.LIKELY,
        kind=CheckKind.INFO,
        impact="Missing rate limits increase abuse risk on public RPCs.",
        remediation="Enforce per-IP rate limits at the edge (Nginx, Envoy, Cloudflare).",
        score_impact=0,
        allowed_profiles=(ScanProfile.DEEP,),
    )

    def run(self, client, context):
        if not client.limits.allow_rate_limit_stress:
            return []
        saw_429 = False
        limit_headers = {}
        # Small bounded burst — still respects profile RPS/budget via RpcClient
        for _ in range(3):
            response = client.request_raw(
                json_body={
                    "jsonrpc": "2.0",
                    "id": 900001,
                    "method": "eth_blockNumber",
                    "params": [],
                }
            )
            if response.status_code == 429:
                saw_429 = True
            for key in ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"):
                if key in response.headers:
                    limit_headers[key] = response.headers[key]
        context["rate_limit_probe"] = {"saw_429": saw_429, "headers": limit_headers}
        if saw_429 or limit_headers:
            return [
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    score_impact=0,
                    evidence={"saw_429": saw_429, "headers": limit_headers},
                    description=(
                        "Rate limiting signals observed"
                        + (" (HTTP 429)" if saw_429 else "")
                        + (f" headers={limit_headers}" if limit_headers else "")
                        + "."
                    ),
                )
            ]
        return [
            self.finding(
                title="No rate-limit signals in light burst",
                severity=Severity.LOW,
                kind=CheckKind.FINDING,
                score_impact=4,
                evidence={"burst": 3, "saw_429": False, "headers": {}},
                description=(
                    "A short eth_blockNumber burst did not return HTTP 429 or common "
                    "rate-limit headers. Confirm edge rate limiting separately."
                ),
            )
        ]


def namespace_rules() -> list[Rule]:
    return [
        NamespaceExposureRule(rule_id, method, severity, score, ns)
        for rule_id, method, severity, score, ns in NAMESPACE_PROBES
    ]
