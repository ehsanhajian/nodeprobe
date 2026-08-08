"""Sui GraphQL RPC surface scanner.

Sui Foundation fullnodes disabled the deprecated JSON-RPC API in July 2026.
This engine targets the current GraphQL RPC endpoint instead.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import httpx

from nodeprobe import __version__, killswitch
from nodeprobe.killswitch import KillSwitchActive
from nodeprobe.models import CheckKind, Finding, ScanError, ScanProfile, ScanResult, Severity
from nodeprobe.multichain.common import finding, probe_tls, split_findings
from nodeprobe.profiles import ProfileLimits, get_profile
from nodeprobe.rpc import BudgetExceeded, RpcClient
from nodeprobe.safety import UnsafeTargetError, mask_credentials, validate_target
from nodeprobe.scoring import compute_score


_IDENTITY_QUERY = """
query NodeprobeIdentity {
  chainIdentifier
  checkpoint {
    sequenceNumber
    digest
    timestamp
  }
}
"""

_INTROSPECTION_QUERY = """
query NodeprobeSchema {
  __schema {
    queryType { name }
    mutationType {
      name
      fields { name }
    }
  }
}
"""

SUI_RULE_CATALOG = [
    {
        "rule_id": "SUI-IDENT-001",
        "title": "Sui chain identity",
        "category": "Identity",
    },
    {
        "rule_id": "SUI-IDENT-002",
        "title": "Sui latest checkpoint",
        "category": "Identity",
    },
    {
        "rule_id": "SUI-GQL-001",
        "title": "GraphQL schema introspection",
        "category": "Disclosure",
    },
    {
        "rule_id": "SUI-GQL-002",
        "title": "GraphQL mutation surface",
        "category": "Namespaces",
    },
    {
        "rule_id": "SUI-LEGACY-001",
        "title": "Deprecated Sui JSON-RPC surface",
        "category": "Legacy API",
    },
    {
        "rule_id": "MC-TLS-001",
        "title": "TLS certificate validation",
        "category": "TLS Security",
    },
]


class SuiScannerEngine:
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
        network_name = "Sui"
        client_version = None

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                if not self.skip_tls_probe:
                    produced.extend(probe_tls(target.original_url))

                identity, identity_errors, identity_status = graphql_query(
                    client, _IDENTITY_QUERY
                )
                chain_identifier = (
                    identity.get("chainIdentifier")
                    if isinstance(identity, dict)
                    else None
                )
                checkpoint = (
                    identity.get("checkpoint")
                    if isinstance(identity, dict)
                    and isinstance(identity.get("checkpoint"), dict)
                    else None
                )

                if identity_status != 200 or not chain_identifier:
                    produced.append(
                        finding(
                            rule_id="SUI-IDENT-001",
                            title="Sui GraphQL identity query failed",
                            category="Identity",
                            severity=Severity.HIGH,
                            kind=CheckKind.FINDING,
                            description=(
                                "GraphQL did not return Sui chainIdentifier. "
                                f"HTTP {identity_status}."
                            ),
                            evidence={
                                "status": identity_status,
                                "errors": _trim(identity_errors),
                            },
                            impact="The endpoint is unavailable, incompatible, or unhealthy.",
                            remediation=(
                                "Verify the Sui GraphQL RPC URL and service health. "
                                "JSON-RPC endpoints are no longer supported."
                            ),
                            score_impact=20,
                        )
                    )
                else:
                    produced.append(
                        finding(
                            rule_id="SUI-IDENT-001",
                            title="Sui chain identity",
                            category="Identity",
                            severity=Severity.INFO,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=(
                                "GraphQL returned the network genesis checkpoint digest."
                            ),
                            evidence={"chain_identifier": chain_identifier},
                        )
                    )

                if checkpoint:
                    timestamp = checkpoint.get("timestamp")
                    age_seconds = _checkpoint_age_seconds(timestamp)
                    stale = age_seconds is not None and age_seconds > 300
                    produced.append(
                        finding(
                            rule_id="SUI-IDENT-002",
                            title=(
                                "Sui latest checkpoint appears stale"
                                if stale
                                else "Sui latest checkpoint available"
                            ),
                            category="Identity",
                            severity=Severity.MEDIUM if stale else Severity.INFO,
                            kind=CheckKind.FINDING if stale else CheckKind.EXPECTED_SURFACE,
                            description=(
                                f"Latest checkpoint sequence={checkpoint.get('sequenceNumber')}, "
                                f"timestamp={timestamp}."
                            ),
                            evidence={
                                "sequence_number": checkpoint.get("sequenceNumber"),
                                "digest": checkpoint.get("digest"),
                                "timestamp": timestamp,
                                "age_seconds": age_seconds,
                            },
                            impact=(
                                "A stale checkpoint can indicate an unhealthy or lagging data service."
                                if stale
                                else ""
                            ),
                            remediation=(
                                "Check the GraphQL indexer/fullnode data path and upstream health."
                                if stale
                                else ""
                            ),
                            score_impact=10 if stale else 0,
                        )
                    )

                if self.limits.name in {ScanProfile.STANDARD, ScanProfile.DEEP}:
                    schema, schema_errors, schema_status = graphql_query(
                        client, _INTROSPECTION_QUERY
                    )
                    schema_data = (
                        schema.get("__schema")
                        if isinstance(schema, dict)
                        and isinstance(schema.get("__schema"), dict)
                        else None
                    )
                    if schema_data:
                        produced.append(
                            finding(
                                rule_id="SUI-GQL-001",
                                title="Sui GraphQL introspection enabled",
                                category="Disclosure",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    "The public endpoint exposes GraphQL schema introspection."
                                ),
                                evidence={
                                    "query_type": schema_data.get("queryType"),
                                    "status": schema_status,
                                },
                                impact=(
                                    "Schema introspection makes API reconnaissance easier."
                                ),
                                remediation=(
                                    "Disable introspection on public production gateways if "
                                    "clients do not require it, or apply query controls."
                                ),
                                score_impact=4,
                            )
                        )

                        mutation_type = schema_data.get("mutationType")
                        mutation_fields = (
                            mutation_type.get("fields")
                            if isinstance(mutation_type, dict)
                            else []
                        ) or []
                        mutation_names = [
                            item.get("name")
                            for item in mutation_fields
                            if isinstance(item, dict) and item.get("name")
                        ]
                        if mutation_names:
                            produced.append(
                                finding(
                                    rule_id="SUI-GQL-002",
                                    title="Sui GraphQL mutation surface advertised",
                                    category="Namespaces",
                                    severity=Severity.INFO,
                                    kind=CheckKind.EXPECTED_SURFACE,
                                    description=(
                                        f"Schema advertises {len(mutation_names)} mutation(s). "
                                        "No mutation was executed."
                                    ),
                                    evidence={"mutations": mutation_names[:20]},
                                    impact=(
                                        "Transaction mutations are expected but need gateway "
                                        "rate limits and abuse controls."
                                    ),
                                    remediation=(
                                        "Allow only required mutations and enforce rate, size, "
                                        "depth, and complexity limits."
                                    ),
                                )
                            )
                    elif schema_errors:
                        produced.append(
                            finding(
                                rule_id="SUI-GQL-001",
                                title="Sui GraphQL introspection blocked",
                                category="Disclosure",
                                severity=Severity.INFO,
                                kind=CheckKind.EXPECTED_SURFACE,
                                description=(
                                    "Schema introspection was rejected or unavailable."
                                ),
                                evidence={
                                    "status": schema_status,
                                    "errors": _trim(schema_errors),
                                },
                            )
                        )

                if self.limits.name == ScanProfile.DEEP:
                    legacy_available, detail = legacy_jsonrpc_probe(
                        client,
                        "sui_getChainIdentifier"
                    )
                    if legacy_available:
                        produced.append(
                            finding(
                                rule_id="SUI-LEGACY-001",
                                title="Deprecated Sui JSON-RPC still exposed",
                                category="Legacy API",
                                severity=Severity.LOW,
                                kind=CheckKind.FINDING,
                                description=(
                                    "`sui_getChainIdentifier` is still recognized on this "
                                    "endpoint although Sui JSON-RPC is deprecated."
                                ),
                                evidence={
                                    "method": "sui_getChainIdentifier",
                                    "detail": _trim(detail),
                                },
                                impact=(
                                    "Maintaining the retired API increases attack and "
                                    "maintenance surface."
                                ),
                                remediation=(
                                    "Migrate clients to GraphQL or gRPC and remove legacy "
                                    "JSON-RPC exposure."
                                ),
                                score_impact=4,
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


def graphql_query(
    client: RpcClient, query: str
) -> tuple[dict[str, Any] | None, list[Any], int]:
    """Run one budgeted, read-only GraphQL query."""
    client._enforce_budget()  # noqa: SLF001
    started = time.monotonic()
    response = client._client.post(  # noqa: SLF001
        client.target.original_url,
        json={"query": query},
        headers={"Accept": "application/json"},
    )
    client._record(response, started)  # noqa: SLF001
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return None, [{"message": (response.text or "")[:300]}], response.status_code
    if not isinstance(payload, dict):
        return None, [{"message": "GraphQL response was not an object"}], response.status_code
    data = payload.get("data")
    errors = payload.get("errors") or []
    return data if isinstance(data, dict) else None, errors, response.status_code


def legacy_jsonrpc_probe(client: RpcClient, method: str) -> tuple[bool, Any]:
    """Presence-probe one deprecated JSON-RPC method without raising on HTTP 4xx."""
    client._enforce_budget()  # noqa: SLF001
    started = time.monotonic()
    response = client._client.post(  # noqa: SLF001
        client.target.original_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": []},
    )
    client._record(response, started)  # noqa: SLF001
    if response.status_code >= 400:
        return False, {"status": response.status_code}
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
        if code in {-32601, -32004} or "not found" in message:
            return False, error
        return True, error
    return "result" in payload, payload.get("result")


def looks_like_sui_graphql(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and isinstance(payload.get("data"), dict)
        and isinstance(payload["data"].get("chainIdentifier"), str)
        and bool(payload["data"]["chainIdentifier"])
    )


def _checkpoint_age_seconds(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


def _trim(value: Any, limit: int = 240) -> Any:
    text = str(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return value
