"""Aptos fullnode REST API surface scanner (/v1)."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from nodeprobe import __version__, killswitch
from nodeprobe.escalation import (
    _child,
    max_escalations_for,
    profile_allows_escalation,
)
from nodeprobe.killswitch import KillSwitchActive
from nodeprobe.models import CheckKind, Finding, ScanError, ScanProfile, ScanResult, Severity
from nodeprobe.multichain.common import finding, probe_tls, split_findings
from nodeprobe.profiles import ProfileLimits, get_profile
from nodeprobe.rpc import BudgetExceeded, RpcClient
from nodeprobe.safety import UnsafeTargetError, mask_credentials, validate_target
from nodeprobe.scoring import compute_score

# Path probes relative to /v1 — GET unless noted.
# (path, severity, score_impact, min_profile, kind_hint)
_SENSITIVE_GETS = (
    (
        "/info",
        "Low",
        4,
        ScanProfile.QUICK,
        "Node /info discloses build and runtime metadata.",
    ),
    (
        "/spec",
        "Low",
        4,
        ScanProfile.STANDARD,
        "OpenAPI HTML/spec exposure aids API reconnaissance.",
    ),
    (
        "/spec.yaml",
        "Low",
        3,
        ScanProfile.DEEP,
        "Raw OpenAPI YAML exposes the full HTTP surface.",
    ),
    (
        "/spec.json",
        "Low",
        3,
        ScanProfile.DEEP,
        "Raw OpenAPI JSON exposes the full HTTP surface.",
    ),
)

_PROFILE_RANK = {
    ScanProfile.QUICK: 0,
    ScanProfile.STANDARD: 1,
    ScanProfile.DEEP: 2,
}

APTOS_RULE_CATALOG = [
    {"rule_id": "APT-IDENT-001", "title": "Aptos ledger / chain identity", "category": "Identity"},
    {"rule_id": "APT-IDENT-002", "title": "Aptos health check", "category": "Identity"},
    {"rule_id": "APT-DISC-001", "title": "Aptos /info or OpenAPI disclosure", "category": "Disclosure"},
    {"rule_id": "APT-NS-001", "title": "Aptos simulate / submit surface", "category": "Namespaces"},
    {"rule_id": "MC-TLS-001", "title": "TLS certificate validation", "category": "TLS Security"},
]


def _profile_at_least(current: ScanProfile, minimum: ScanProfile) -> bool:
    return _PROFILE_RANK[current] >= _PROFILE_RANK[minimum]


def normalize_aptos_base(url: str) -> str:
    """Return origin + /v1 (no trailing slash beyond /v1)."""
    parsed = urlparse(url)
    path = (parsed.path or "").rstrip("/")
    if path.endswith("/v1"):
        base_path = path
    elif path.endswith("/v1/"):
        base_path = path.rstrip("/")
    else:
        base_path = f"{path}/v1" if path else "/v1"
    return urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", ""))


class AptosScannerEngine:
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
        network_name = "Aptos"
        client_version = None
        chain_id: int | None = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            base = normalize_aptos_base(target.original_url)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                ledger, ledger_status = _rest_get(client, base, "")
                if ledger_status >= 400 or not isinstance(ledger, dict):
                    produced.append(
                        finding(
                            rule_id="APT-IDENT-001",
                            title="Aptos ledger info failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description="GET /v1 did not return Aptos ledger info.",
                            evidence={"status": ledger_status, "body": _trim(ledger)},
                            score_impact=20,
                        )
                    )
                else:
                    chain_id = _as_int(ledger.get("chain_id"))
                    network_name = f"Aptos chain_id={chain_id}" if chain_id is not None else "Aptos"
                    client_version = ledger.get("git_hash")
                    role = ledger.get("node_role")
                    produced.append(
                        finding(
                            rule_id="APT-IDENT-001",
                            title="Aptos ledger info",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"chain_id={chain_id}, role={role}, "
                                f"ledger_version={ledger.get('ledger_version')}."
                            ),
                            evidence={
                                "chain_id": chain_id,
                                "node_role": role,
                                "ledger_version": ledger.get("ledger_version"),
                                "epoch": ledger.get("epoch"),
                                "git_hash": client_version,
                            },
                        )
                    )
                    if role and str(role).lower() in {"validator", "validator_full_node"}:
                        produced.append(
                            finding(
                                rule_id="APT-IDENT-001",
                                title=f"Aptos node_role is {role}",
                                category="Identity",
                                severity=Severity.MEDIUM,
                                kind=CheckKind.FINDING,
                                description=(
                                    f"Public endpoint reports node_role={role}. "
                                    "Validator-facing APIs should not be public."
                                ),
                                evidence={"node_role": role},
                                impact="Validator/full-validator exposure increases attack surface.",
                                remediation="Expose only full_node (or a gateway) publicly; keep validators private.",
                                score_impact=12,
                            )
                        )

                healthy, health_status = _rest_get(client, base, "/-/healthy")
                if health_status == 200:
                    produced.append(
                        finding(
                            rule_id="APT-IDENT-002",
                            title="Aptos health endpoint OK",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description="GET /v1/-/healthy returned 200.",
                            evidence={"status": health_status, "body": _trim(healthy)},
                        )
                    )
                elif health_status:
                    produced.append(
                        finding(
                            rule_id="APT-IDENT-002",
                            title="Aptos health endpoint unhealthy",
                            category="Identity",
                            severity=Severity.MEDIUM,
                            kind=CheckKind.FINDING,
                            description=f"GET /v1/-/healthy returned HTTP {health_status}.",
                            evidence={"status": health_status, "body": _trim(healthy)},
                            score_impact=8,
                        )
                    )

                for path, sev_name, impact, min_profile, note in _SENSITIVE_GETS:
                    if not _profile_at_least(self.limits.name, min_profile):
                        continue
                    body, status = _rest_get(client, base, path)
                    if status == 200:
                        produced.append(
                            finding(
                                rule_id="APT-DISC-001",
                                title=f"Aptos disclosure path exposed: {path}",
                                category="Disclosure",
                                severity=Severity[sev_name.upper()],
                                kind=CheckKind.FINDING,
                                description=f"GET /v1{path} returned 200. {note}",
                                evidence={
                                    "path": path,
                                    "status": status,
                                    "bytes": len(str(body)),
                                    "snippet": _trim(body, 120),
                                },
                                impact=note,
                                remediation=(
                                    "Front Aptos fullnodes with a gateway; hide /info and OpenAPI "
                                    "spec paths on public edges."
                                ),
                                score_impact=impact,
                            )
                        )

                # Simulate / submit — presence only (expect 4xx with empty/invalid body).
                if _profile_at_least(self.limits.name, ScanProfile.STANDARD):
                    sim_body, sim_status = _rest_post(
                        client, base, "/transactions/simulate", json_body={}
                    )
                    if sim_status not in {0, 404, 405}:
                        # 400/403/415 still mean the route exists
                        produced.append(
                            finding(
                                rule_id="APT-NS-001",
                                title="Aptos transaction simulate endpoint exposed",
                                category="Namespaces",
                                severity=Severity.MEDIUM,
                                kind=CheckKind.FINDING,
                                description=(
                                    f"POST /v1/transactions/simulate returned HTTP {sim_status} "
                                    "(route present on this public node)."
                                ),
                                evidence={
                                    "path": "/transactions/simulate",
                                    "status": sim_status,
                                    "detail": _trim(sim_body),
                                },
                                impact="Public simulate aids reconnaissance and can be abused for load.",
                                remediation="Rate-limit or authenticate simulate on public gateways.",
                                score_impact=10,
                            )
                        )

                    sub_body, sub_status = _rest_post(
                        client, base, "/transactions", json_body={}
                    )
                    if sub_status not in {0, 404, 405}:
                        produced.append(
                            finding(
                                rule_id="APT-NS-001",
                                title="Aptos transaction submit endpoint exposed",
                                category="Namespaces",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    f"POST /v1/transactions returned HTTP {sub_status} "
                                    "(expected on public fullnodes; confirm auth/rate limits)."
                                ),
                                evidence={
                                    "path": "/transactions",
                                    "status": sub_status,
                                    "detail": _trim(sub_body),
                                },
                                impact="Submit without gateway controls enables spam / mempool abuse.",
                                remediation="Keep submit public only behind rate limits and abuse controls.",
                                score_impact=4,
                            )
                        )

                produced.extend(_run_aptos_escalations(client, base, produced))
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
            chain_id=chain_id,
            network_name=network_name,
            client_version=str(client_version) if client_version else None,
            score=score,
            findings=findings,
            expected_surface=expected,
            errors=errors,
            aborted=aborted,
            abort_reason=abort_reason,
        )


def _run_aptos_escalations(
    client: RpcClient, base: str, findings: list[Finding]
) -> list[Finding]:
    profile = client.limits.name
    if not profile_allows_escalation(profile):
        return []
    budget = max_escalations_for(profile)
    out: list[Finding] = []
    for parent in findings:
        if len(out) >= budget:
            break
        if parent.parent_rule_id or parent.kind != CheckKind.FINDING:
            continue
        if parent.severity not in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}:
            continue
        path = str((parent.evidence or {}).get("path") or "")
        if parent.rule_id == "APT-DISC-001" and path == "/info":
            body, status = _rest_get(client, base, "/spec")
            if status == 200:
                kid = _child(
                    parent=parent,
                    step="SIBLING",
                    title="Sibling path also exposed: /spec",
                    severity=Severity.LOW,
                    kind=CheckKind.FINDING,
                    description="After /info, OpenAPI /spec is also reachable.",
                    evidence={"parent_path": path, "path": "/spec", "status": status},
                    score_impact=3,
                )
                parent.evidence = {
                    **(parent.evidence or {}),
                    "escalation_ran": True,
                    "escalation_children": [kid.rule_id],
                }
                out.append(kid)
        elif parent.rule_id == "APT-NS-001" and path == "/transactions/simulate":
            body, status = _rest_post(client, base, "/transactions", json_body={})
            if status not in {0, 404, 405}:
                kid = _child(
                    parent=parent,
                    step="SIBLING",
                    title="Sibling submit route also exposed: /transactions",
                    severity=Severity.LOW,
                    kind=CheckKind.FINDING,
                    description=(
                        f"Simulate exposure followed by submit HTTP {status} on the same node."
                    ),
                    evidence={
                        "parent_path": path,
                        "path": "/transactions",
                        "status": status,
                        "detail": _trim(body),
                    },
                    score_impact=3,
                )
                parent.evidence = {
                    **(parent.evidence or {}),
                    "escalation_ran": True,
                    "escalation_children": [kid.rule_id],
                }
                out.append(kid)
    return out


def _rest_get(client: RpcClient, base: str, path: str) -> tuple[Any, int]:
    url = base if not path else base.rstrip("/") + path
    client._enforce_budget()  # noqa: SLF001
    t0 = time.monotonic()
    response = client._client.get(url)  # noqa: SLF001
    client._record(response, t0)  # noqa: SLF001
    return _decode_body(response), response.status_code


def _rest_post(
    client: RpcClient, base: str, path: str, *, json_body: dict[str, Any]
) -> tuple[Any, int]:
    url = base.rstrip("/") + path
    client._enforce_budget()  # noqa: SLF001
    t0 = time.monotonic()
    response = client._client.post(url, json=json_body)  # noqa: SLF001
    client._record(response, t0)  # noqa: SLF001
    return _decode_body(response), response.status_code


def _decode_body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except json.JSONDecodeError:
        text = response.text or ""
        return text[:500] if text else {"__http_error__": response.status_code}


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _trim(value: Any, limit: int = 200) -> Any:
    text = str(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return value


def looks_like_aptos_ledger(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and "chain_id" in payload
        and "ledger_version" in payload
        and "node_role" in payload
    )
