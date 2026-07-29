"""Finding-driven escalation: confirm impact after High/Critical signals.

Quick: no escalations.
Standard: cheap confirmations (bounded).
Deep: sibling probes + slightly richer summaries (still no exploit payloads).
"""

from __future__ import annotations

from typing import Any, Callable

from dapptility_scanner.models import (
    CheckKind,
    Confidence,
    Finding,
    ScanProfile,
    Severity,
)
from dapptility_scanner.rpc import RpcClient

EscalationFn = Callable[[RpcClient, dict[str, Any], Finding], list[Finding]]

_ESCALATE_FROM = {
    Severity.CRITICAL,
    Severity.HIGH,
}


def _trim(value: Any, limit: int = 120) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "..."
    if isinstance(value, dict):
        return {k: _trim(v, limit) for k, v in list(value.items())[:12]}
    if isinstance(value, list):
        return [_trim(v, limit) for v in value[:8]]
    return value


def _child(
    *,
    parent: Finding,
    step: str,
    title: str,
    severity: Severity,
    kind: CheckKind,
    description: str,
    evidence: dict[str, Any],
    score_impact: int,
    impact: str = "",
    remediation: str = "",
) -> Finding:
    return Finding(
        rule_id=f"{parent.rule_id}-{step}",
        title=title,
        category="Escalation",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        kind=kind,
        description=description,
        evidence={"escalation_of": parent.rule_id, **evidence},
        impact=impact or parent.impact,
        remediation=remediation or parent.remediation,
        references=list(parent.references),
        score_impact=score_impact,
        parent_rule_id=parent.rule_id,
    )


def _escalate_eth_accounts(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    result = client.call("eth_accounts")
    if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
        return [
            _child(
                parent=parent,
                step="CONFIRM",
                title="eth_accounts escalation: method no longer usable",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description="Follow-up eth_accounts call failed; initial presence may have been a soft signal.",
                evidence={"response": _trim(result)},
                score_impact=0,
            )
        ]
    accounts = result if isinstance(result, list) else []
    out: list[Finding] = []

    if not accounts:
        out.append(
            _child(
                parent=parent,
                step="CONFIRM",
                title="Next: eth_accounts returns empty list",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description=(
                    "Follow-up confirmed eth_accounts works and returned []. "
                    "No local accounts disclosed — probing related privileged methods next."
                ),
                evidence={"account_count": 0, "accounts": [], "step": "confirm_empty"},
                score_impact=6,
                impact="Unfiltered eth_accounts aids recon even when empty.",
                remediation="Deny eth_accounts on public RPC gateways.",
            )
        )
    else:
        sample = [str(a) for a in accounts[:3]]
        evidence: dict[str, Any] = {
            "account_count": len(accounts),
            "accounts_sample": sample,
            "step": "accounts_disclosed",
        }
        if client.limits.name == ScanProfile.DEEP and sample:
            bal = client.call("eth_getBalance", [sample[0], "latest"])
            if not (isinstance(bal, dict) and ("__rpc_error__" in bal or "__http_error__" in bal)):
                evidence["sample_balance"] = bal
        out.append(
            _child(
                parent=parent,
                step="IMPACT",
                title=f"Next: eth_accounts disclosed {len(accounts)} account(s)",
                severity=Severity.CRITICAL,
                kind=CheckKind.FINDING,
                description=(
                    f"Follow-up pulled {len(accounts)} account(s) from eth_accounts. "
                    "Public RPCs should never expose node-local accounts."
                ),
                evidence=evidence,
                score_impact=30,
                impact="Disclosed accounts enable targeted recon and amplify unlocked-key risk.",
                remediation="Disable eth_accounts; never unlock keys on public listeners.",
            )
        )

    # Always take attacker-style next steps after eth_accounts hits
    next_probes = [
        ("personal_listAccounts", "personal_* account listing"),
        ("personal_listWallets", "personal_* wallet listing"),
        ("eth_sendTransaction", "unlocked-account send path"),
        ("personal_sendTransaction", "personal send path"),
    ]
    if client.limits.name == ScanProfile.DEEP:
        next_probes.extend(
            [
                ("personal_newAccount", "account creation API"),
                ("eth_sign", "eth_sign on node keys"),
            ]
        )

    exposed: list[str] = []
    blocked: list[str] = []
    details: dict[str, Any] = {}
    for method, _label in next_probes:
        ok, detail = client.method_available(method)
        if ok:
            exposed.append(method)
            details[method] = _trim(detail)
        else:
            blocked.append(method)

    if exposed:
        out.append(
            _child(
                parent=parent,
                step="NEXT",
                title=f"Next: {len(exposed)} related privileged method(s) also open",
                severity=Severity.CRITICAL
                if any(m.startswith("personal_") or m == "eth_sendTransaction" for m in exposed)
                else Severity.HIGH,
                kind=CheckKind.FINDING,
                description=(
                    "After eth_accounts, follow-up probes found related methods available: "
                    + ", ".join(exposed)
                    + "."
                ),
                evidence={
                    "step": "related_methods",
                    "exposed": exposed,
                    "blocked": blocked,
                    "details": details,
                },
                score_impact=25 if any(m.startswith("personal_") for m in exposed) else 15,
                impact="Combined eth_accounts + personal/send surface is a high-value attack path.",
                remediation="Allowlist only public read methods; deny personal_* and eth_sendTransaction.",
            )
        )
    else:
        out.append(
            _child(
                parent=parent,
                step="NEXT",
                title="Next: related personal/send methods appear blocked",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description=(
                    "Follow-up after eth_accounts: personal_* / eth_sendTransaction probes "
                    "were not available (good). eth_accounts itself is still unfiltered."
                ),
                evidence={"step": "related_methods", "exposed": [], "blocked": blocked},
                score_impact=0,
                impact="Attackers will keep probing other namespaces, but signing paths look closed.",
                remediation="Still deny eth_accounts on the public gateway.",
            )
        )
    return out


def _escalate_admin(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    result = client.call("admin_nodeInfo")
    if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
        # try sibling
        ok, detail = client.method_available("admin_peers")
        if ok:
            return [
                _child(
                    parent=parent,
                    step="SIBLING",
                    title="admin_* sibling method also exposed",
                    severity=Severity.CRITICAL,
                    kind=CheckKind.FINDING,
                    description="admin_nodeInfo follow-up failed but admin_peers appears available.",
                    evidence={"sibling": "admin_peers", "detail": _trim(detail)},
                    score_impact=15,
                )
            ]
        return []
    if not isinstance(result, dict):
        return []
    safe = {
        "name": _trim(result.get("name")),
        "enode": _trim(str(result.get("enode") or "")[:48]),
        "ip": result.get("ip"),
        "listenAddr": _trim(result.get("listenAddr")),
        "protocols": list((result.get("protocols") or {}).keys())
        if isinstance(result.get("protocols"), dict)
        else None,
    }
    return [
        _child(
            parent=parent,
            step="IMPACT",
            title="admin_nodeInfo returned live node metadata",
            severity=Severity.CRITICAL,
            kind=CheckKind.FINDING,
            description=(
                "Escalation retrieved admin_nodeInfo fields (name/enode truncated). "
                "Admin API is enabled on this public listener."
            ),
            evidence={"node_info": safe},
            score_impact=25,
            impact="Admin metadata leaks topology and can aid node targeting.",
            remediation="Bind admin API to localhost; never expose admin_* publicly.",
        )
    ]


def _escalate_personal(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    result = client.call("personal_listAccounts")
    if isinstance(result, dict) and ("__rpc_error__" in result or "__http_error__" in result):
        ok, detail = client.method_available("personal_listWallets")
        if ok:
            return [
                _child(
                    parent=parent,
                    step="SIBLING",
                    title="personal_* sibling method also exposed",
                    severity=Severity.CRITICAL,
                    kind=CheckKind.FINDING,
                    description="personal_listAccounts follow-up failed but personal_listWallets appears available.",
                    evidence={"sibling": "personal_listWallets", "detail": _trim(detail)},
                    score_impact=20,
                )
            ]
        return []
    accounts = result if isinstance(result, list) else []
    return [
        _child(
            parent=parent,
            step="IMPACT",
            title=f"personal_listAccounts returned {len(accounts)} account(s)",
            severity=Severity.CRITICAL,
            kind=CheckKind.FINDING,
            description=(
                "Escalation confirmed personal namespace data access on a public endpoint."
            ),
            evidence={
                "account_count": len(accounts),
                "accounts_sample": [str(a) for a in accounts[:3]],
            },
            score_impact=35,
            impact="personal_* on a public RPC is a direct key-management risk.",
            remediation="Disable personal namespace entirely on public listeners.",
        )
    ]


def _escalate_debug(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    ok, detail = client.method_available("debug_memStats")
    if not ok:
        ok2, detail2 = client.method_available("debug_verbosity")
        if ok2:
            return [
                _child(
                    parent=parent,
                    step="SIBLING",
                    title="debug_* sibling method also exposed",
                    severity=Severity.CRITICAL,
                    kind=CheckKind.FINDING,
                    description="debug_memStats unavailable but debug_verbosity appears exposed.",
                    evidence={"sibling": "debug_verbosity", "detail": _trim(detail2)},
                    score_impact=15,
                )
            ]
        return []
    keys = list(detail.keys())[:15] if isinstance(detail, dict) else []
    return [
        _child(
            parent=parent,
            step="CONFIRM",
            title="debug_memStats confirms debug API",
            severity=Severity.CRITICAL,
            kind=CheckKind.FINDING,
            description="Escalation confirmed debug_memStats responds (keys summarized only).",
            evidence={"memstats_keys": keys, "raw": _trim(detail) if not keys else None},
            score_impact=20,
            impact="Debug APIs can leak memory/runtime internals.",
            remediation="Disable debug_* on public RPC endpoints.",
        )
    ]


def _escalate_txpool(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    status = client.call("txpool_status")
    if isinstance(status, dict) and ("__rpc_error__" in status or "__http_error__" in status):
        return []
    return [
        _child(
            parent=parent,
            step="CONFIRM",
            title="txpool_status returned pool counters",
            severity=Severity.MEDIUM,
            kind=CheckKind.FINDING,
            description="Escalation confirmed txpool data is readable via txpool_status.",
            evidence={"status": _trim(status)},
            score_impact=8,
            impact="Txpool visibility aids sandwich/recon strategies against pending txs.",
            remediation="Restrict txpool_* on public gateways.",
        )
    ]


def _escalate_engine(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    for sibling in ("engine_exchangeCapabilities", "engine_getClientVersionV1"):
        ok, detail = client.method_available(sibling)
        if ok:
            return [
                _child(
                    parent=parent,
                    step="SIBLING",
                    title=f"engine_* sibling exposed: {sibling}",
                    severity=Severity.CRITICAL,
                    kind=CheckKind.FINDING,
                    description=f"Escalation found related engine method `{sibling}` available.",
                    evidence={"sibling": sibling, "detail": _trim(detail)},
                    score_impact=20,
                    impact="Engine API exposure can threaten consensus-layer safety.",
                    remediation="Never expose engine_* on the public internet.",
                )
            ]
    return []


def _escalate_miner(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    ok, detail = client.method_available("eth_mining")
    if not ok:
        ok, detail = client.method_available("miner_getHashrate")
    if not ok:
        return []
    return [
        _child(
            parent=parent,
            step="SIBLING",
            title="Mining-related method also exposed",
            severity=Severity.HIGH,
            kind=CheckKind.FINDING,
            description="Escalation confirmed additional mining/control surface on this RPC.",
            evidence={"detail": _trim(detail)},
            score_impact=12,
            remediation="Disable miner_* / mining controls on public endpoints.",
        )
    ]


def _escalate_trace(client: RpcClient, context: dict, parent: Finding) -> list[Finding]:
    ok, detail = client.method_available("trace_replayBlockTransactions")
    if not ok:
        ok, detail = client.method_available("trace_filter")
    if not ok:
        return []
    return [
        _child(
            parent=parent,
            step="SIBLING",
            title="Additional trace_* method exposed",
            severity=Severity.HIGH,
            kind=CheckKind.FINDING,
            description="Escalation found related trace namespace methods available.",
            evidence={"detail": _trim(detail)},
            score_impact=10,
            remediation="Restrict trace_* to authenticated internal callers.",
        )
    ]


# parent_rule_id → ordered escalation callbacks
EVM_ESCALATIONS: dict[str, list[EscalationFn]] = {
    "EVM-NS-ACCOUNTS": [_escalate_eth_accounts],
    "EVM-NS-ADMIN": [_escalate_admin],
    "EVM-NS-PERSONAL": [_escalate_personal],
    "EVM-NS-DEBUG": [_escalate_debug],
    "EVM-NS-TXPOOL": [_escalate_txpool],
    "EVM-NS-ENGINE": [_escalate_engine],
    "EVM-NS-MINER": [_escalate_miner],
    "EVM-NS-TRACE": [_escalate_trace],
}


def profile_allows_escalation(profile: ScanProfile) -> bool:
    return profile in {ScanProfile.STANDARD, ScanProfile.DEEP}


def max_escalations_for(profile: ScanProfile) -> int:
    if profile == ScanProfile.DEEP:
        return 12
    if profile == ScanProfile.STANDARD:
        return 6
    return 0


def run_evm_escalations(
    client: RpcClient,
    context: dict[str, Any],
    findings: list[Finding],
) -> list[Finding]:
    """Run follow-ups for High/Critical parent findings. Returns new child findings only."""
    profile = client.limits.name
    if not profile_allows_escalation(profile):
        return []

    budget = max_escalations_for(profile)
    produced: list[Finding] = []
    seen_parents: set[str] = set()

    # Parents only (skip prior escalations)
    parents = [
        f
        for f in findings
        if f.parent_rule_id is None
        and f.kind == CheckKind.FINDING
        and f.severity in _ESCALATE_FROM
        and f.rule_id in EVM_ESCALATIONS
    ]
    # Worst first
    parents.sort(key=lambda f: (0 if f.severity == Severity.CRITICAL else 1, f.rule_id))

    for parent in parents:
        if parent.rule_id in seen_parents:
            continue
        seen_parents.add(parent.rule_id)
        for fn in EVM_ESCALATIONS[parent.rule_id]:
            if len(produced) >= budget:
                return produced
            try:
                kids = fn(client, context, parent)
            except Exception:  # noqa: BLE001 — escalation must not kill the scan
                kids = []
            for kid in kids:
                produced.append(kid)
                if len(produced) >= budget:
                    return produced
    return produced


def run_method_sibling_escalations(
    client: RpcClient,
    findings: list[Finding],
    *,
    siblings_by_method: dict[str, tuple[str, ...]],
    rule_prefix: str,
) -> list[Finding]:
    """For High/Critical method-exposure findings, probe configured siblings."""
    profile = client.limits.name
    if not profile_allows_escalation(profile):
        return []
    budget = max_escalations_for(profile)
    produced: list[Finding] = []
    for parent in findings:
        if len(produced) >= budget:
            break
        if parent.parent_rule_id is not None:
            continue
        if parent.kind != CheckKind.FINDING or parent.severity not in _ESCALATE_FROM:
            continue
        method = str((parent.evidence or {}).get("method") or "")
        siblings = siblings_by_method.get(method) or ()
        for sibling in siblings:
            if len(produced) >= budget:
                break
            ok, detail = client.method_available(sibling)
            if not ok:
                continue
            produced.append(
                _child(
                    parent=parent,
                    step="SIBLING",
                    title=f"Sibling method also exposed: {sibling}",
                    severity=parent.severity,
                    kind=CheckKind.FINDING,
                    description=(
                        f"Escalation from `{method}` confirmed related method `{sibling}`."
                    ),
                    evidence={
                        "parent_method": method,
                        "sibling": sibling,
                        "detail": _trim(detail),
                        "family": rule_prefix,
                    },
                    score_impact=min(15, max(6, parent.score_impact // 2 or 8)),
                )
            )
            break
    return produced


SOLANA_SIBLINGS = {
    "validatorExit": ("setLogFilter",),
    "setLogFilter": ("validatorExit",),
    "requestAirdrop": ("getIdentity",),
}

SUBSTRATE_SIBLINGS = {
    "author_rotateKeys": ("author_insertKey", "author_hasKey"),
    "author_insertKey": ("author_rotateKeys",),
    "offchain_localStorageSet": ("offchain_localStorageGet",),
    "offchain_localStorageGet": ("offchain_localStorageSet",),
    "author_submitExtrinsic": ("author_pendingExtrinsics",),
}

COSMOS_SIBLINGS = {
    "dial_seeds": ("dial_peers",),
    "dial_peers": ("dial_seeds",),
    "unsafe_flush_mempool": ("dial_peers", "dial_seeds"),
}
