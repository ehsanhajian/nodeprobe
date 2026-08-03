"""Substrate / Polkadot JSON-RPC surface scanner."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from nodeprobe import __version__, killswitch
from nodeprobe.escalation import SUBSTRATE_SIBLINGS, run_method_sibling_escalations
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

_SENSITIVE_METHODS = (
    ("author_rotateKeys", "Critical", 35),
    ("author_insertKey", "Critical", 35),
    ("offchain_localStorageSet", "High", 18),
    ("offchain_localStorageGet", "High", 15),
    ("author_submitExtrinsic", "Medium", 8),
)

SUBSTRATE_RULE_CATALOG = [
    {"rule_id": "SUB-IDENT-001", "title": "Substrate chain identity", "category": "Identity"},
    {"rule_id": "SUB-IDENT-002", "title": "system_health", "category": "Identity"},
    {"rule_id": "SUB-DISC-001", "title": "rpc_methods catalog disclosure", "category": "Disclosure"},
    {"rule_id": "SUB-NS-001", "title": "Sensitive Substrate method exposure", "category": "Namespaces"},
    {"rule_id": "MC-TLS-001", "title": "TLS certificate validation", "category": "TLS Security"},
]


class SubstrateScannerEngine:
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
        produced: list = []
        aborted = False
        abort_reason = None
        requests_made = 0
        network_name = "Substrate"
        client_version = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                chain = client.call("system_chain")
                name = client.call("system_name")
                version = client.call("system_version")
                if is_rpc_failure(chain):
                    produced.append(
                        finding(
                            rule_id="SUB-IDENT-001",
                            title="system_chain failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description="Endpoint did not return system_chain.",
                            evidence={"response": chain},
                            score_impact=20,
                        )
                    )
                else:
                    network_name = str(chain)
                    if not is_rpc_failure(version):
                        client_version = str(version)
                    produced.append(
                        finding(
                            rule_id="SUB-IDENT-001",
                            title="Substrate chain identity",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Connected to {chain}"
                                + (f" ({name})" if not is_rpc_failure(name) else "")
                                + (f" v{version}" if not is_rpc_failure(version) else "")
                                + "."
                            ),
                            evidence={
                                "chain": chain,
                                "name": name if not is_rpc_failure(name) else None,
                                "version": version if not is_rpc_failure(version) else None,
                            },
                        )
                    )

                health = client.call("system_health")
                if not is_rpc_failure(health) and isinstance(health, dict):
                    is_syncing = bool(health.get("isSyncing"))
                    peers = health.get("peers")
                    produced.append(
                        finding(
                            rule_id="SUB-IDENT-002",
                            title="system_health",
                            category="Identity",
                            severity=Severity.MEDIUM if is_syncing else Severity.INFO,
                            kind=CheckKind.FINDING if is_syncing else CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Node peers={peers}, isSyncing={is_syncing}."
                            ),
                            evidence={"health": health},
                            score_impact=6 if is_syncing else 0,
                        )
                    )

                methods = client.call("rpc_methods")
                if not is_rpc_failure(methods):
                    method_list: list[str] = []
                    if isinstance(methods, dict):
                        raw = methods.get("methods") or methods.get("result") or []
                        if isinstance(raw, list):
                            method_list = [str(m) for m in raw]
                    elif isinstance(methods, list):
                        method_list = [str(m) for m in methods]
                    if method_list:
                        produced.append(
                            finding(
                                rule_id="SUB-DISC-001",
                                title="rpc_methods catalog disclosed",
                                category="Disclosure",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    f"Endpoint lists {len(method_list)} RPC methods via rpc_methods."
                                ),
                                evidence={
                                    "method_count": len(method_list),
                                    "sample": method_list[:20],
                                },
                                impact="Full method catalogs speed up attacker recon.",
                                remediation="Restrict rpc_methods on public endpoints when possible.",
                                score_impact=4,
                            )
                        )

                for method, sev_name, impact in _SENSITIVE_METHODS:
                    if method.startswith("author_rotate") and self.limits.name == ScanProfile.QUICK:
                        continue
                    available, detail = client.method_available(method)
                    if available:
                        produced.append(
                            finding(
                                rule_id="SUB-NS-001",
                                title=f"Sensitive method exposed: {method}",
                                category="Namespaces",
                                severity=Severity[sev_name.upper()],
                                kind=CheckKind.FINDING,
                                description=f"RPC accepts or recognizes `{method}`.",
                                evidence={"method": method, "detail": _trim(detail)},
                                impact="Privileged Substrate methods increase takeover / key risk.",
                                remediation="Expose only safe public methods behind an RPC gateway.",
                                score_impact=impact,
                            )
                        )

                findings_so_far, _ = split_findings(produced)
                produced.extend(
                    run_method_sibling_escalations(
                        client,
                        findings_so_far,
                        siblings_by_method=SUBSTRATE_SIBLINGS,
                        rule_prefix="substrate",
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
