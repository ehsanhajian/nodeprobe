"""Cosmos / Tendermint RPC surface scanner (JSON-RPC + REST)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from nodeprobe import __version__, killswitch
from nodeprobe.escalation import COSMOS_SIBLINGS, run_method_sibling_escalations
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

_UNSAFE_JSON_RPC = (
    ("dial_seeds", "High", 18),
    ("dial_peers", "High", 18),
    ("unsafe_flush_mempool", "Critical", 30),
)

COSMOS_RULE_CATALOG = [
    {"rule_id": "COS-IDENT-001", "title": "Tendermint / Cosmos status", "category": "Identity"},
    {"rule_id": "COS-DISC-001", "title": "net_info peer disclosure", "category": "Disclosure"},
    {"rule_id": "COS-NS-001", "title": "Unsafe Tendermint method exposure", "category": "Namespaces"},
    {"rule_id": "MC-TLS-001", "title": "TLS certificate validation", "category": "TLS Security"},
]


class CosmosScannerEngine:
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
        network_name = "Cosmos"
        client_version = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                status = client.call("status")
                if is_rpc_failure(status):
                    # Fall back to Tendermint REST GET /status
                    status = _rest_get_json(client, "status")
                if is_rpc_failure(status) or not isinstance(status, dict):
                    produced.append(
                        finding(
                            rule_id="COS-IDENT-001",
                            title="Tendermint status failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description="Endpoint did not return Tendermint status.",
                            evidence={"response": status},
                            score_impact=20,
                        )
                    )
                else:
                    # REST wraps under "result"
                    payload = status.get("result", status) if isinstance(status, dict) else status
                    if not isinstance(payload, dict):
                        payload = status
                    node_info = payload.get("node_info") or {}
                    sync = payload.get("sync_info") or {}
                    network_name = str(
                        node_info.get("network")
                        or node_info.get("id")
                        or "Cosmos"
                    )
                    client_version = (
                        node_info.get("version")
                        or node_info.get("moniker")
                    )
                    catching_up = bool(sync.get("catching_up"))
                    produced.append(
                        finding(
                            rule_id="COS-IDENT-001",
                            title="Tendermint / Cosmos node status",
                            category="Identity",
                            severity=Severity.MEDIUM if catching_up else Severity.INFO,
                            kind=CheckKind.FINDING if catching_up else CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Network {network_name}, catching_up={catching_up}."
                            ),
                            evidence={
                                "network": network_name,
                                "moniker": node_info.get("moniker"),
                                "version": node_info.get("version"),
                                "catching_up": catching_up,
                            },
                            score_impact=6 if catching_up else 0,
                        )
                    )

                if self.limits.name != ScanProfile.QUICK:
                    net_info = client.call("net_info")
                    if is_rpc_failure(net_info):
                        net_info = _rest_get_json(client, "net_info")
                    if not is_rpc_failure(net_info) and isinstance(net_info, dict):
                        payload = net_info.get("result", net_info)
                        peers = []
                        if isinstance(payload, dict):
                            peers = payload.get("peers") or []
                        if isinstance(peers, list) and peers:
                            produced.append(
                                finding(
                                    rule_id="COS-DISC-001",
                                    title="net_info peer listing enabled",
                                    category="Disclosure",
                                    severity=Severity.MEDIUM,
                                    kind=CheckKind.FINDING,
                                    description=f"Endpoint returned {len(peers)} peer entries.",
                                    evidence={"peer_count": len(peers)},
                                    impact="Peer listings aid reconnaissance of validator topology.",
                                    remediation="Restrict net_info on public Tendermint RPC ports.",
                                    score_impact=10,
                                )
                            )

                for method, sev_name, impact in _UNSAFE_JSON_RPC:
                    if self.limits.name == ScanProfile.QUICK and method.startswith("unsafe"):
                        continue
                    available, detail = client.method_available(method)
                    if available:
                        produced.append(
                            finding(
                                rule_id="COS-NS-001",
                                title=f"Unsafe Tendermint method exposed: {method}",
                                category="Namespaces",
                                severity=Severity[sev_name.upper()],
                                kind=CheckKind.FINDING,
                                description=f"RPC accepts or recognizes `{method}`.",
                                evidence={"method": method, "detail": _trim(detail)},
                                impact="Unsafe Tendermint RPC methods can disrupt the node.",
                                remediation="Bind Tendermint RPC privately; disable unsafe APIs.",
                                score_impact=impact,
                            )
                        )

                findings_so_far, _ = split_findings(produced)
                produced.extend(
                    run_method_sibling_escalations(
                        client,
                        findings_so_far,
                        siblings_by_method=COSMOS_SIBLINGS,
                        rule_prefix="cosmos",
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
            client_version=str(client_version) if client_version else None,
            score=score,
            findings=findings,
            expected_surface=expected,
            errors=errors,
            aborted=aborted,
            abort_reason=abort_reason,
        )


def _rest_get_json(client: RpcClient, path: str) -> Any:
    """GET {origin}/{path} for Tendermint REST fallback."""
    import time

    parsed = urlparse(client.target.original_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    url = urljoin(root + "/", path.lstrip("/"))
    client._enforce_budget()  # noqa: SLF001 — shared budget with JSON-RPC calls
    t0 = time.monotonic()
    response = client._client.get(url)  # noqa: SLF001
    client._record(response, t0)  # noqa: SLF001
    if response.status_code >= 400:
        return {"__http_error__": response.status_code}
    try:
        return response.json()
    except json.JSONDecodeError:
        return {"__http_error__": "invalid_json"}


def _trim(value: Any) -> Any:
    text = str(value)
    if len(text) > 200:
        return text[:197] + "..."
    return value
