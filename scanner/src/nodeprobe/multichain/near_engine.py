"""NEAR JSON-RPC surface scanner."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from nodeprobe import __version__, killswitch
from nodeprobe.killswitch import KillSwitchActive
from nodeprobe.models import CheckKind, Finding, ScanError, ScanProfile, ScanResult, Severity
from nodeprobe.multichain.common import finding, is_rpc_failure, probe_tls, split_findings
from nodeprobe.profiles import ProfileLimits, get_profile
from nodeprobe.rpc import BudgetExceeded, RpcClient
from nodeprobe.safety import UnsafeTargetError, mask_credentials, validate_target
from nodeprobe.scoring import compute_score


_ADVERSARIAL_METHODS = (
    "adv_disable_header_sync",
    "adv_disable_doomslug",
    "adv_produce_blocks",
    "adv_produce_chunks",
    "adv_switch_to_height",
    "adv_get_saved_blocks",
    "adv_check_store",
    "sandbox_patch_state",
    "sandbox_fast_forward",
)

_CONFIG_METHODS = (
    "client_config",
    "genesis_config",
    "EXPERIMENTAL_genesis_config",
    "EXPERIMENTAL_protocol_config",
)

_SUBMISSION_METHODS = (
    "send_tx",
    "broadcast_tx_async",
    "broadcast_tx_commit",
)

_INVENTORY_METHODS = (
    "status",
    "health",
    "network_info",
    "validators",
    "block",
    "chunk",
    "query",
    "gas_price",
    "protocol_config",
    "tx",
    "EXPERIMENTAL_changes",
    "EXPERIMENTAL_changes_in_block",
    "EXPERIMENTAL_congestion_level",
)

_INVALID_PARAMS = [{"nodeprobe_invalid_presence_probe": True}]


NEAR_RULE_CATALOG = [
    {"rule_id": "NEAR-IDENT-001", "title": "NEAR chain identity", "category": "Identity"},
    {"rule_id": "NEAR-IDENT-002", "title": "NEAR sync / health status", "category": "Identity"},
    {"rule_id": "NEAR-ADV-001", "title": "Adversarial or sandbox RPC exposure", "category": "Namespaces"},
    {"rule_id": "NEAR-DISC-001", "title": "Network peer disclosure", "category": "Disclosure"},
    {"rule_id": "NEAR-DISC-002", "title": "Node configuration method exposure", "category": "Disclosure"},
    {"rule_id": "NEAR-DISC-003", "title": "Public method inventory", "category": "Disclosure"},
    {"rule_id": "NEAR-NS-001", "title": "Transaction submission surface", "category": "Namespaces"},
    {"rule_id": "MC-TLS-001", "title": "TLS certificate validation", "category": "TLS Security"},
]


class NearScannerEngine:
    def __init__(
        self,
        url: str,
        profile: str | ScanProfile | ProfileLimits = "Standard",
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
        produced: list[Finding] = []
        aborted = False
        abort_reason = None
        requests_made = 0
        network_name = "NEAR"
        client_version = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                status = client.call("status")
                if not looks_like_near_status(status):
                    produced.append(
                        finding(
                            rule_id="NEAR-IDENT-001",
                            title="NEAR chain identity failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description="Endpoint did not return a valid NEAR status response.",
                            evidence={"response": _trim(status)},
                            impact="The endpoint may be unavailable, incompatible, or unhealthy.",
                            remediation="Verify the NEAR JSON-RPC URL and node health.",
                            score_impact=20,
                        )
                    )
                    sync_info: dict[str, Any] = {}
                else:
                    chain_id = str(status.get("chain_id"))
                    network_name = _network_name(chain_id)
                    version = status.get("version")
                    client_version = _client_version(version)
                    sync_info = (
                        status.get("sync_info")
                        if isinstance(status.get("sync_info"), dict)
                        else {}
                    )
                    produced.append(
                        finding(
                            rule_id="NEAR-IDENT-001",
                            title="NEAR chain identity",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Chain {chain_id}; nearcore {client_version or 'unknown'}."
                            ),
                            evidence={
                                "chain_id": chain_id,
                                "version": version,
                                "protocol_version": status.get("protocol_version"),
                                "latest_protocol_version": status.get(
                                    "latest_protocol_version"
                                ),
                            },
                        )
                    )

                syncing = bool(sync_info.get("syncing"))
                health = client.call("health")
                health_failed = is_rpc_failure(health)
                unhealthy = syncing or health_failed
                produced.append(
                    finding(
                        rule_id="NEAR-IDENT-002",
                        title=(
                            "NEAR node is syncing"
                            if syncing
                            else "NEAR health check failed"
                            if health_failed
                            else "NEAR sync / health status"
                        ),
                        category="Identity",
                        severity=Severity.MEDIUM if unhealthy else Severity.INFO,
                        kind=CheckKind.FINDING if unhealthy else CheckKind.EXPECTED_SURFACE,
                        description=(
                            "Node reports an active synchronization operation."
                            if syncing
                            else "The health method returned an RPC error."
                            if health_failed
                            else (
                                f"Latest block height: "
                                f"{sync_info.get('latest_block_height')}; healthy and synced."
                            )
                        ),
                        evidence={
                            "syncing": syncing,
                            "latest_block_height": sync_info.get("latest_block_height"),
                            "latest_block_time": sync_info.get("latest_block_time"),
                            "health": _trim(health),
                        },
                        impact=(
                            "A syncing or unhealthy node may return incomplete or stale data."
                            if unhealthy
                            else ""
                        ),
                        remediation=(
                            "Wait for synchronization or route traffic to a healthy node."
                            if unhealthy
                            else ""
                        ),
                        score_impact=8 if unhealthy else 0,
                    )
                )

                if self.limits.name in {ScanProfile.STANDARD, ScanProfile.DEEP}:
                    network_info = client.call("network_info")
                    if isinstance(network_info, dict) and not is_rpc_failure(network_info):
                        active_peers = network_info.get("active_peers")
                        known_producers = network_info.get("known_producers")
                        peer_count = (
                            len(active_peers) if isinstance(active_peers, list) else 0
                        )
                        producer_count = (
                            len(known_producers)
                            if isinstance(known_producers, list)
                            else 0
                        )
                        if peer_count or producer_count:
                            produced.append(
                                finding(
                                    rule_id="NEAR-DISC-001",
                                    title="NEAR network topology disclosed",
                                    category="Disclosure",
                                    severity=Severity.MEDIUM,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"network_info returned {peer_count} active peer(s) "
                                        f"and {producer_count} known producer(s)."
                                    ),
                                    evidence={
                                        "active_peer_count": peer_count,
                                        "known_producer_count": producer_count,
                                    },
                                    impact=(
                                        "Peer and producer details aid reconnaissance of node "
                                        "and validator topology."
                                    ),
                                    remediation=(
                                        "Restrict network_info on public RPC gateways or "
                                        "filter topology details."
                                    ),
                                    score_impact=10,
                                )
                            )

                    config_methods: list[str] = []
                    for method in _CONFIG_METHODS:
                        available, _ = near_method_available(client, method)
                        if available:
                            config_methods.append(method)
                    if config_methods:
                        produced.append(
                            finding(
                                rule_id="NEAR-DISC-002",
                                title="NEAR node configuration methods exposed",
                                category="Disclosure",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    "The endpoint recognizes configuration methods. "
                                    "Only invalid-parameter presence probes were sent."
                                ),
                                evidence={"methods": config_methods},
                                impact=(
                                    "Node and protocol configuration can reveal deployment "
                                    "details useful for reconnaissance."
                                ),
                                remediation=(
                                    "Restrict configuration methods on public gateways when "
                                    "clients do not require them."
                                ),
                                score_impact=5,
                            )
                        )

                    for method in _ADVERSARIAL_METHODS:
                        available, detail = near_method_available(client, method)
                        if available:
                            produced.append(
                                finding(
                                    rule_id="NEAR-ADV-001",
                                    title=f"NEAR test control method exposed: {method}",
                                    category="Namespaces",
                                    severity=Severity.CRITICAL,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"RPC recognizes `{method}`. No control action was executed."
                                    ),
                                    evidence={
                                        "method": method,
                                        "detail": _trim(detail),
                                    },
                                    impact=(
                                        "Adversarial and sandbox methods can manipulate sync, "
                                        "consensus behavior, blocks, or chain state."
                                    ),
                                    remediation=(
                                        "Run production nearcore without test/sandbox features "
                                        "and block these methods at the public gateway."
                                    ),
                                    score_impact=30,
                                )
                            )

                    submission_methods: list[str] = []
                    for method in _SUBMISSION_METHODS:
                        available, _ = near_method_available(client, method)
                        if available:
                            submission_methods.append(method)
                    if submission_methods:
                        produced.append(
                            finding(
                                rule_id="NEAR-NS-001",
                                title="NEAR transaction submission surface",
                                category="Namespaces",
                                severity=Severity.INFO,
                                kind=CheckKind.EXPECTED_SURFACE,
                                description=(
                                    "The endpoint recognizes transaction-submission methods. "
                                    "No transaction was submitted."
                                ),
                                evidence={"methods": submission_methods},
                                impact=(
                                    "Submission is normal for public RPC but can be abused "
                                    "without gateway controls."
                                ),
                                remediation=(
                                    "Enforce payload limits, rate limits, and upstream "
                                    "transaction-pool protections."
                                ),
                            )
                        )

                if self.limits.name == ScanProfile.DEEP:
                    exposed: list[str] = []
                    missing: list[str] = []
                    for method in _INVENTORY_METHODS:
                        available, _ = near_method_available(client, method)
                        (exposed if available else missing).append(method)
                    produced.append(
                        finding(
                            rule_id="NEAR-DISC-003",
                            title="Public NEAR method inventory",
                            category="Disclosure",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Probed {len(_INVENTORY_METHODS)} common methods: "
                                f"{len(exposed)} available, {len(missing)} missing."
                            ),
                            evidence={
                                "exposed": exposed,
                                "missing": missing,
                                "probed": list(_INVENTORY_METHODS),
                            },
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
        score = 0 if abort_reason == "unsafe_target" else compute_score(findings)
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


def looks_like_near_status(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("chain_id"), str)
        and bool(value["chain_id"])
        and isinstance(value.get("sync_info"), dict)
        and isinstance(value.get("version"), dict)
    )


def near_method_available(client: RpcClient, method: str) -> tuple[bool, Any]:
    """Presence-probe a method while tolerating NEAR's HTTP 400 RPC errors."""
    response = client.request_raw(
        json_body={
            "jsonrpc": "2.0",
            "id": "nodeprobe",
            "method": method,
            "params": _INVALID_PARAMS,
        }
    )
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return False, {"status": response.status_code, "body": response.text[:200]}
    if not isinstance(payload, dict):
        return False, payload
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        message = str(error.get("message") or "").lower()
        data = str(error.get("data") or "").lower()
        if code in {-32601, -32004} or "method not found" in message or "unknown method" in data:
            return False, error
        return True, error
    return "result" in payload, payload.get("result")


def _network_name(chain_id: str) -> str:
    names = {"mainnet": "NEAR Mainnet", "testnet": "NEAR Testnet"}
    return names.get(chain_id.lower(), f"NEAR ({chain_id})")


def _client_version(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    version = value.get("version")
    build = value.get("build")
    if version and build:
        return f"{version} ({build})"
    return str(version or build) if version or build else None


def _trim(value: Any, limit: int = 240) -> Any:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
