from __future__ import annotations

from dapptility_scanner.chains import parse_hex_or_int, resolve_chain
from dapptility_scanner.models import CheckKind, Confidence, Finding, Severity
from dapptility_scanner.rules.base import Rule, RuleMeta


class ChainIdRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-IDENT-001",
        title="Chain ID resolved",
        description="Endpoint responds to eth_chainId with a resolvable network.",
        category="Network Identity",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.EXPECTED_SURFACE,
    )

    def run(self, client, context):
        result = client.call("eth_chainId")
        if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
            return [
                self.finding(
                    title="eth_chainId failed",
                    severity=Severity.HIGH,
                    kind=CheckKind.FINDING,
                    confidence=Confidence.CONFIRMED,
                    description="Endpoint did not return a usable Chain ID.",
                    evidence={"response": result},
                    score_impact=25,
                )
            ]
        chain_id = parse_hex_or_int(result)
        info = resolve_chain(chain_id)
        context["chain_id"] = chain_id
        context["network_name"] = info.name
        description = f"Chain ID {chain_id} mapped to {info.name}."
        if not info.listed:
            description = (
                f"Chain ID {chain_id} is not in the local Chainlist snapshot; "
                f"continuing as {info.name}."
            )
        return [
            self.finding(
                evidence={
                    "chain_id": chain_id,
                    "network": info.name,
                    "listed": info.listed,
                },
                description=description,
            )
        ]


class NetVersionRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-IDENT-002",
        title="net_version consistency",
        description="Compare net_version with eth_chainId when both are available.",
        category="Network Identity",
        severity=Severity.MEDIUM,
        confidence=Confidence.LIKELY,
        kind=CheckKind.FINDING,
        impact="Inconsistent network identity can indicate misconfiguration or a wrong backend.",
        remediation="Ensure all RPC methods resolve to the same intended network.",
        score_impact=15,
    )

    def run(self, client, context):
        chain_id = context.get("chain_id")
        if chain_id is None:
            return []
        result = client.call("net_version")
        if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
            return []
        try:
            net_version = parse_hex_or_int(result)
        except (TypeError, ValueError):
            return []
        context["net_version"] = net_version
        if net_version != chain_id:
            return [
                self.finding(
                    evidence={"chain_id": chain_id, "net_version": net_version},
                    description=(
                        f"eth_chainId ({chain_id}) does not match net_version ({net_version})."
                    ),
                )
            ]
        return [
            Finding(
                rule_id=self.meta.rule_id,
                title="net_version matches chain ID",
                category=self.meta.category,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                kind=CheckKind.EXPECTED_SURFACE,
                description="net_version matches eth_chainId.",
                evidence={"chain_id": chain_id, "net_version": net_version},
            )
        ]


class BlockNumberRule(Rule):
    meta = RuleMeta(
        rule_id="EVM-IDENT-003",
        title="Block number available",
        description="Endpoint returns eth_blockNumber.",
        category="Network Identity",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.EXPECTED_SURFACE,
    )

    def run(self, client, context):
        result = client.call("eth_blockNumber")
        if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
            return [
                self.finding(
                    title="eth_blockNumber failed",
                    severity=Severity.HIGH,
                    kind=CheckKind.FINDING,
                    description="Public RPC did not return a block number.",
                    evidence={"response": result},
                    score_impact=20,
                )
            ]
        block = parse_hex_or_int(result)
        context["block_number"] = block
        if block <= 0:
            return [
                self.finding(
                    title="Stale or empty chain tip",
                    severity=Severity.MEDIUM,
                    kind=CheckKind.FINDING,
                    confidence=Confidence.LIKELY,
                    description="eth_blockNumber returned 0 or a non-positive value.",
                    evidence={"block_number": block},
                    score_impact=10,
                )
            ]
        return [
            self.finding(
                evidence={"block_number": block},
                description=f"Latest block number is {block}.",
            )
        ]
