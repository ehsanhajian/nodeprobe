"""Solana JSON-RPC surface scanner."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from nodeprobe import __version__, killswitch
from nodeprobe.escalation import SOLANA_SIBLINGS, run_method_sibling_escalations
from nodeprobe.killswitch import KillSwitchActive
from nodeprobe.models import CheckKind, ScanError, ScanProfile, ScanResult, Severity
from nodeprobe.multichain.common import (
    finding,
    is_rpc_failure,
    probe_tls,
    split_findings,
)
from nodeprobe.profiles import ProfileLimits, get_profile
from nodeprobe.rpc import BudgetExceeded, RpcClient
from nodeprobe.safety import UnsafeTargetError, mask_credentials, validate_target
from nodeprobe.scoring import compute_score

# Presence probes — not executed with expensive payloads.
# (method, severity, score_impact, remediation, min_profile)
_SENSITIVE_METHODS = (
    (
        "validatorExit",
        "Critical",
        35,
        "Node exit control should never be exposed publicly.",
        ScanProfile.STANDARD,
    ),
    (
        "setLogFilter",
        "High",
        18,
        "Log filter control indicates privileged RPC surface.",
        ScanProfile.STANDARD,
    ),
    (
        "requestAirdrop",
        "Medium",
        8,
        "Airdrop method on a public RPC is unexpected for mainnet.",
        ScanProfile.QUICK,
    ),
    (
        "getProgramAccounts",
        "Medium",
        10,
        "Unbounded getProgramAccounts enables expensive enumeration / DoS.",
        ScanProfile.STANDARD,
    ),
    (
        "getLargestAccounts",
        "Low",
        4,
        "Largest-account listings aid wealth and whale reconnaissance.",
        ScanProfile.STANDARD,
    ),
    (
        "getTokenLargestAccounts",
        "Low",
        4,
        "Token whale listings aid reconnaissance on public RPCs.",
        ScanProfile.DEEP,
    ),
    (
        "getLeaderSchedule",
        "Low",
        3,
        "Leader schedules map validator topology beyond normal tip queries.",
        ScanProfile.DEEP,
    ),
)

# Common public methods — Deep inventory only (expected surface, not scored as vulns).
_INVENTORY_METHODS = (
    "getHealth",
    "getVersion",
    "getSlot",
    "getBalance",
    "getAccountInfo",
    "getLatestBlockhash",
    "getBlockHeight",
    "getTransaction",
    "sendTransaction",
    "simulateTransaction",
    "getSignatureStatuses",
    "getMultipleAccounts",
)

_PROFILE_RANK = {
    ScanProfile.QUICK: 0,
    ScanProfile.STANDARD: 1,
    ScanProfile.DEEP: 2,
}


def _profile_at_least(current: ScanProfile, minimum: ScanProfile) -> bool:
    return _PROFILE_RANK[current] >= _PROFILE_RANK[minimum]


SOLANA_RULE_CATALOG = [
    {"rule_id": "SOL-IDENT-001", "title": "Solana health / version", "category": "Identity"},
    {"rule_id": "SOL-IDENT-002", "title": "Cluster slot / epoch", "category": "Identity"},
    {"rule_id": "SOL-DISC-001", "title": "getIdentity disclosure", "category": "Disclosure"},
    {"rule_id": "SOL-DISC-002", "title": "getClusterNodes peer listing", "category": "Disclosure"},
    {"rule_id": "SOL-DISC-003", "title": "Public method inventory", "category": "Disclosure"},
    {"rule_id": "SOL-NS-001", "title": "Sensitive Solana method exposure", "category": "Namespaces"},
    {"rule_id": "MC-TLS-001", "title": "TLS certificate validation", "category": "TLS Security"},
]


class SolanaScannerEngine:
    def __init__(
        self,
        url: str,
        profile: str | ScanProfile | ProfileLimits = "Quick",
        *,
        http_client: httpx.Client | None = None,
        skip_tls_probe: bool = False,
        resolve_dns: bool = True,
    ):
        if isinstance(profile, ProfileLimits):
            self.limits = profile
        elif isinstance(profile, ScanProfile):
            self.limits = get_profile(profile.value)
        else:
            self.limits = get_profile(profile)
        self.url = url
        self.http_client = http_client
        self.skip_tls_probe = skip_tls_probe
        self.resolve_dns = resolve_dns

    def run(self) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[ScanError] = []
        produced: list = []
        aborted = False
        abort_reason = None
        requests_made = 0
        network_name = "Solana"
        client_version = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                health = client.call("getHealth")
                if is_rpc_failure(health):
                    produced.append(
                        finding(
                            rule_id="SOL-IDENT-001",
                            title="getHealth failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description="Endpoint did not return Solana getHealth=ok.",
                            evidence={"response": health},
                            score_impact=20,
                        )
                    )
                elif health != "ok":
                    produced.append(
                        finding(
                            rule_id="SOL-IDENT-001",
                            title="Solana node unhealthy",
                            category="Identity",
                            severity=Severity.MEDIUM,
                            kind=CheckKind.FINDING,
                            description=f"getHealth returned {health!r}.",
                            evidence={"health": health},
                            score_impact=10,
                        )
                    )
                else:
                    produced.append(
                        finding(
                            rule_id="SOL-IDENT-001",
                            title="Solana node healthy",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description="getHealth returned ok.",
                            evidence={"health": health},
                        )
                    )

                version = client.call("getVersion")
                if not is_rpc_failure(version) and isinstance(version, dict):
                    client_version = version.get("solana-core") or str(version)
                    network_name = "Solana"
                    produced.append(
                        finding(
                            rule_id="SOL-IDENT-001",
                            title="Solana client version",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=f"solana-core {client_version}.",
                            evidence={"version": version},
                        )
                    )

                slot = client.call("getSlot")
                epoch = client.call("getEpochInfo")
                if not is_rpc_failure(slot) or not is_rpc_failure(epoch):
                    produced.append(
                        finding(
                            rule_id="SOL-IDENT-002",
                            title="Cluster tip available",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description="Endpoint returns slot / epoch information.",
                            evidence={"slot": slot, "epoch": epoch},
                        )
                    )

                identity = client.call("getIdentity")
                if not is_rpc_failure(identity):
                    produced.append(
                        finding(
                            rule_id="SOL-DISC-001",
                            title="getIdentity discloses node pubkey",
                            category="Disclosure",
                            severity=Severity.LOW,
                            kind=CheckKind.FINDING,
                            description="Public RPC returns the node identity pubkey.",
                            evidence={"identity": identity},
                            impact="Identity leakage helps map infrastructure ownership.",
                            remediation="Front public RPCs with a gateway that strips getIdentity if not needed.",
                            score_impact=4,
                        )
                    )

                if self.limits.name == ScanProfile.DEEP:
                    nodes = client.call("getClusterNodes")
                    if not is_rpc_failure(nodes) and isinstance(nodes, list):
                        produced.append(
                            finding(
                                rule_id="SOL-DISC-002",
                                title="getClusterNodes peer listing enabled",
                                category="Disclosure",
                                severity=Severity.MEDIUM,
                                kind=CheckKind.FINDING,
                                description=(
                                    f"Endpoint returned {len(nodes)} cluster node entries."
                                ),
                                evidence={"node_count": len(nodes)},
                                impact="Peer listings aid reconnaissance of the cluster topology.",
                                remediation="Disable getClusterNodes on public gateways when possible.",
                                score_impact=10,
                            )
                        )

                for method, sev_name, impact, remediation, min_profile in _SENSITIVE_METHODS:
                    if not _profile_at_least(self.limits.name, min_profile):
                        continue
                    available, detail = client.method_available(method)
                    if available:
                        produced.append(
                            finding(
                                rule_id="SOL-NS-001",
                                title=f"Sensitive method exposed: {method}",
                                category="Namespaces",
                                severity=Severity[sev_name.upper()],
                                kind=CheckKind.FINDING,
                                description=f"RPC accepts or recognizes `{method}`.",
                                evidence={"method": method, "detail": _trim(detail)},
                                impact=remediation,
                                remediation=(
                                    "Disable privileged or expensive Solana methods on public "
                                    "endpoints; allowlist only required read methods."
                                ),
                                score_impact=impact,
                            )
                        )

                if self.limits.name == ScanProfile.DEEP:
                    exposed: list[str] = []
                    missing: list[str] = []
                    for method in _INVENTORY_METHODS:
                        available, _detail = client.method_available(method)
                        if available:
                            exposed.append(method)
                        else:
                            missing.append(method)
                    produced.append(
                        finding(
                            rule_id="SOL-DISC-003",
                            title="Public Solana method inventory",
                            category="Disclosure",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Probed {len(_INVENTORY_METHODS)} common public methods: "
                                f"{len(exposed)} available, {len(missing)} missing."
                            ),
                            evidence={
                                "exposed": exposed,
                                "missing": missing,
                                "probed": list(_INVENTORY_METHODS),
                            },
                            score_impact=0,
                        )
                    )

                findings_so_far, _ = split_findings(produced)
                produced.extend(
                    run_method_sibling_escalations(
                        client,
                        findings_so_far,
                        siblings_by_method=SOLANA_SIBLINGS,
                        rule_prefix="solana",
                    )
                )

                requests_made = client.requests_made

        except KillSwitchActive as exc:
            aborted = True
            abort_reason = "kill_switch"
            errors.append(ScanError(code="kill_switch", message=str(exc)))
        except UnsafeTargetError as exc:
            aborted = True
            abort_reason = "unsafe_target"
            errors.append(ScanError(code="unsafe_target", message=str(exc)))
        except BudgetExceeded as exc:
            aborted = True
            abort_reason = "budget"
            errors.append(ScanError(code="aborted", message=str(exc)))
        except Exception as exc:  # noqa: BLE001
            aborted = True
            abort_reason = "scan_error"
            errors.append(ScanError(code="scan_error", message=str(exc)))

        findings, expected = split_findings(produced)
        finished = datetime.now(timezone.utc)
        score = 0 if abort_reason in {"unsafe_target"} else compute_score(findings)
        return ScanResult(
            scanner_version=__version__,
            profile=self.limits.name,
            endpoint=mask_credentials(self.url),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_ms=int((finished - started).total_seconds() * 1000),
            requests_made=requests_made,
            chain_id=None,
            network_name=network_name,
            client_version=client_version,
            score=score,
            findings=findings,
            expected_surface=expected,
            errors=errors,
            aborted=aborted,
            abort_reason=abort_reason,
        )


def _trim(value: Any) -> Any:
    text = str(value)
    if len(text) > 200:
        return text[:197] + "..."
    return value
