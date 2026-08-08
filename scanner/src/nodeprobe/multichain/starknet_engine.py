"""Starknet JSON-RPC surface scanner."""

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


_DEVNET_METHODS = (
    "devnet_mint",
    "devnet_restart",
    "devnet_load",
    "devnet_dump",
    "devnet_createBlock",
    "devnet_abortBlocks",
    "starknet_generateBlock",
)

_TRACE_METHODS = (
    "starknet_traceTransaction",
    "starknet_traceBlockTransactions",
    "starknet_simulateTransactions",
)

_SUBMISSION_METHODS = (
    "starknet_addInvokeTransaction",
    "starknet_addDeclareTransaction",
    "starknet_addDeployAccountTransaction",
)

_INVENTORY_METHODS = (
    "starknet_chainId",
    "starknet_specVersion",
    "starknet_blockNumber",
    "starknet_blockHashAndNumber",
    "starknet_syncing",
    "starknet_getBlockWithTxHashes",
    "starknet_getBlockWithTxs",
    "starknet_getStateUpdate",
    "starknet_getStorageAt",
    "starknet_getNonce",
    "starknet_call",
    "starknet_estimateFee",
    "starknet_getEvents",
    "starknet_getTransactionByHash",
    "starknet_getTransactionReceipt",
)

_CHAIN_NAMES = {
    "SN_MAIN": "Starknet Mainnet",
    "SN_SEPOLIA": "Starknet Sepolia",
    "SN_INTEGRATION_SEPOLIA": "Starknet Integration Sepolia",
}


STARKNET_RULE_CATALOG = [
    {"rule_id": "STRK-IDENT-001", "title": "Starknet chain identity", "category": "Identity"},
    {"rule_id": "STRK-IDENT-002", "title": "Starknet block / sync status", "category": "Identity"},
    {"rule_id": "STRK-DEV-001", "title": "Devnet control method exposure", "category": "Namespaces"},
    {"rule_id": "STRK-DISC-001", "title": "RPC method catalog disclosure", "category": "Disclosure"},
    {"rule_id": "STRK-DISC-002", "title": "Trace / simulation method surface", "category": "Disclosure"},
    {"rule_id": "STRK-DISC-003", "title": "Public method inventory", "category": "Disclosure"},
    {"rule_id": "STRK-NS-001", "title": "Transaction submission surface", "category": "Namespaces"},
    {"rule_id": "MC-TLS-001", "title": "TLS certificate validation", "category": "TLS Security"},
]


class StarknetScannerEngine:
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
        network_name = "Starknet"
        client_version = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                chain_id = client.call("starknet_chainId")
                spec_version = client.call("starknet_specVersion")
                decoded_chain_id = decode_felt_text(chain_id)
                if is_rpc_failure(chain_id) or not decoded_chain_id:
                    produced.append(
                        finding(
                            rule_id="STRK-IDENT-001",
                            title="Starknet chain identity failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description="Endpoint did not return a valid Starknet chain ID.",
                            evidence={"chain_id": _trim(chain_id)},
                            impact="The endpoint may be unavailable, incompatible, or unhealthy.",
                            remediation="Verify the Starknet JSON-RPC URL and node health.",
                            score_impact=20,
                        )
                    )
                else:
                    network_name = _CHAIN_NAMES.get(
                        decoded_chain_id, f"Starknet ({decoded_chain_id})"
                    )
                    client_version = (
                        str(spec_version) if not is_rpc_failure(spec_version) else None
                    )
                    produced.append(
                        finding(
                            rule_id="STRK-IDENT-001",
                            title="Starknet chain identity",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Chain {decoded_chain_id}; JSON-RPC spec "
                                f"{client_version or 'unknown'}."
                            ),
                            evidence={
                                "chain_id_felt": chain_id,
                                "chain_id_text": decoded_chain_id,
                                "spec_version": client_version,
                            },
                        )
                    )

                block_number = client.call("starknet_blockNumber")
                syncing = client.call("starknet_syncing")
                sync_active = isinstance(syncing, dict) and not is_rpc_failure(syncing)
                identity_failed = is_rpc_failure(block_number)
                produced.append(
                    finding(
                        rule_id="STRK-IDENT-002",
                        title=(
                            "Starknet node is syncing"
                            if sync_active
                            else "Starknet block / sync status"
                        ),
                        category="Identity",
                        severity=(
                            Severity.MEDIUM
                            if sync_active
                            else Severity.HIGH if identity_failed else Severity.INFO
                        ),
                        kind=(
                            CheckKind.FINDING
                            if sync_active or identity_failed
                            else CheckKind.EXPECTED_SURFACE
                        ),
                        description=(
                            "Node reports an active sync operation."
                            if sync_active
                            else f"Latest block number: {block_number}; syncing={syncing}."
                        ),
                        evidence={
                            "block_number": _trim(block_number),
                            "syncing": _trim(syncing),
                        },
                        impact=(
                            "A syncing node may return incomplete or stale data."
                            if sync_active
                            else "RPC health could not be confirmed." if identity_failed else ""
                        ),
                        remediation=(
                            "Wait for synchronization or route traffic to a healthy node."
                            if sync_active
                            else "Check node health and upstream connectivity."
                            if identity_failed
                            else ""
                        ),
                        score_impact=8 if sync_active else 20 if identity_failed else 0,
                    )
                )

                if self.limits.name in {ScanProfile.STANDARD, ScanProfile.DEEP}:
                    available, detail = client.method_available("rpc_methods")
                    if available:
                        methods = _extract_methods(detail)
                        produced.append(
                            finding(
                                rule_id="STRK-DISC-001",
                                title="Starknet RPC method catalog exposed",
                                category="Disclosure",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    "The endpoint exposes its JSON-RPC method catalog."
                                ),
                                evidence={
                                    "method_count": len(methods),
                                    "methods": methods[:50],
                                },
                                impact="A method catalog simplifies endpoint reconnaissance.",
                                remediation=(
                                    "Disable rpc_methods on public gateways when clients do "
                                    "not require discovery."
                                ),
                                score_impact=4,
                            )
                        )

                    for method in _DEVNET_METHODS:
                        method_available, method_detail = client.method_available(method)
                        if method_available:
                            produced.append(
                                finding(
                                    rule_id="STRK-DEV-001",
                                    title=f"Starknet devnet control method exposed: {method}",
                                    category="Namespaces",
                                    severity=Severity.CRITICAL,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"RPC recognizes `{method}`. No control action was executed."
                                    ),
                                    evidence={
                                        "method": method,
                                        "detail": _trim(method_detail),
                                    },
                                    impact=(
                                        "Public devnet controls can alter chain state, restart "
                                        "the node, or expose snapshots."
                                    ),
                                    remediation=(
                                        "Remove devnet APIs from public endpoints and restrict "
                                        "them to an isolated development network."
                                    ),
                                    score_impact=30,
                                )
                            )

                    trace_methods: list[str] = []
                    for method in _TRACE_METHODS:
                        method_available, _ = client.method_available(method)
                        if method_available:
                            trace_methods.append(method)
                    if trace_methods:
                        produced.append(
                            finding(
                                rule_id="STRK-DISC-002",
                                title="Starknet trace / simulation methods exposed",
                                category="Disclosure",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    "The endpoint recognizes trace or simulation methods. "
                                    "Only invalid-parameter presence probes were sent."
                                ),
                                evidence={"methods": trace_methods},
                                impact=(
                                    "Trace and simulation calls can be computationally expensive "
                                    "and useful for detailed reconnaissance."
                                ),
                                remediation=(
                                    "Apply authentication, rate limits, and per-method budgets "
                                    "to trace and simulation APIs."
                                ),
                                score_impact=5,
                            )
                        )

                    submission_methods: list[str] = []
                    for method in _SUBMISSION_METHODS:
                        method_available, _ = client.method_available(method)
                        if method_available:
                            submission_methods.append(method)
                    if submission_methods:
                        produced.append(
                            finding(
                                rule_id="STRK-NS-001",
                                title="Starknet transaction submission surface",
                                category="Namespaces",
                                severity=Severity.INFO,
                                kind=CheckKind.EXPECTED_SURFACE,
                                description=(
                                    "The endpoint accepts transaction-submission method names. "
                                    "No transaction was submitted."
                                ),
                                evidence={"methods": submission_methods},
                                impact=(
                                    "Submission is normal for public RPC but can be abused "
                                    "without gateway controls."
                                ),
                                remediation=(
                                    "Enforce payload limits, rate limits, and upstream "
                                    "mempool protections."
                                ),
                            )
                        )

                if self.limits.name == ScanProfile.DEEP:
                    exposed: list[str] = []
                    missing: list[str] = []
                    for method in _INVENTORY_METHODS:
                        method_available, _ = client.method_available(method)
                        (exposed if method_available else missing).append(method)
                    produced.append(
                        finding(
                            rule_id="STRK-DISC-003",
                            title="Public Starknet method inventory",
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


def decode_felt_text(value: Any) -> str | None:
    """Decode a short-string Starknet chain ID felt such as SN_MAIN."""
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        raw = bytes.fromhex(value[2:])
        decoded = raw.lstrip(b"\x00").decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded and all(32 <= ord(char) < 127 for char in decoded) else None


def looks_like_starknet_chain_id(value: Any) -> bool:
    decoded = decode_felt_text(value)
    return bool(decoded and decoded.startswith("SN_"))


def _extract_methods(value: Any) -> list[str]:
    if isinstance(value, dict):
        value = value.get("methods", [])
    if not isinstance(value, list):
        return []
    return sorted(str(method) for method in value if isinstance(method, str))


def _trim(value: Any, limit: int = 240) -> Any:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
