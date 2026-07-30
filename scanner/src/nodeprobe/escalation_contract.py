"""Finding-driven escalation for EVM contract scans (Standard / Deep)."""

from __future__ import annotations

from typing import Any

from nodeprobe.contract.bytecode import analyze_bytecode
from nodeprobe.escalation import (
    _child,
    _trim,
    max_escalations_for,
    profile_allows_escalation,
)
from nodeprobe.models import CheckKind, Finding, Severity
from nodeprobe.rpc import RpcClient

_OWNER_SELECTOR = "0x8da5cb5b"  # owner()
_ZERO_ADDR = "0x0000000000000000000000000000000000000000"


def _mark_parent(parent: Finding, children: list[Finding]) -> None:
    if not children:
        return
    parent.evidence = {
        **(parent.evidence or {}),
        "escalation_ran": True,
        "escalation_children": [c.rule_id for c in children],
    }


def _decode_address_result(result: Any) -> str | None:
    if not isinstance(result, str) or not result.startswith("0x"):
        return None
    hexdata = result[2:].rjust(64, "0")[-40:]
    if int(hexdata, 16) == 0:
        return _ZERO_ADDR
    return "0x" + hexdata.lower()


def _eth_call_owner(client: RpcClient, address: str) -> tuple[str | None, Any]:
    raw = client.call(
        "eth_call",
        [{"to": address, "data": _OWNER_SELECTOR}, "latest"],
    )
    if isinstance(raw, dict) and ("__rpc_error__" in raw or "__http_error__" in raw):
        return None, raw
    return _decode_address_result(raw), raw


def _escalate_proxy(client: RpcClient, parent: Finding) -> list[Finding]:
    impl = (parent.evidence or {}).get("implementation")
    if not impl or not isinstance(impl, str) or not impl.startswith("0x"):
        return [
            _child(
                parent=parent,
                step="CONFIRM",
                title="Next: proxy detected but implementation unknown",
                severity=Severity.LOW,
                kind=CheckKind.FINDING,
                description="Proxy pattern found without a resolvable implementation address.",
                evidence={"kind": (parent.evidence or {}).get("kind")},
                score_impact=3,
            )
        ]

    code = client.call("eth_getCode", [impl, "latest"])
    if not isinstance(code, str) or code in {"0x", "0x0"}:
        return [
            _child(
                parent=parent,
                step="IMPACT",
                title="Next: proxy implementation has empty code",
                severity=Severity.HIGH,
                kind=CheckKind.FINDING,
                description=f"Implementation {impl} returned empty eth_getCode.",
                evidence={"implementation": impl, "code": "0x"},
                score_impact=15,
                impact="Broken / uninitialized proxies can brick or misroute calls.",
                remediation="Verify implementation is deployed and the proxy admin is controlled.",
            )
        ]

    code_bytes = max(0, (len(code) - 2) // 2)
    hits = analyze_bytecode(code)
    hit_names = {h.name: h.count for h in hits}
    out = [
        _child(
            parent=parent,
            step="CONFIRM",
            title="Next: fetched proxy implementation bytecode",
            severity=Severity.INFO,
            kind=CheckKind.INFO,
            description=f"Implementation {impl} has {code_bytes} bytes of code.",
            evidence={
                "implementation": impl,
                "code_bytes": code_bytes,
                "opcodes": hit_names,
            },
            score_impact=0,
        )
    ]
    if "SELFDESTRUCT" in hit_names:
        out.append(
            _child(
                parent=parent,
                step="DEEPEN",
                title="Next: implementation contains SELFDESTRUCT",
                severity=Severity.HIGH,
                kind=CheckKind.FINDING,
                description=(
                    f"Implementation {impl} bytecode includes SELFDESTRUCT "
                    f"(count={hit_names['SELFDESTRUCT']})."
                ),
                evidence={"implementation": impl, "count": hit_names["SELFDESTRUCT"]},
                score_impact=14,
                impact="Destroying the implementation bricks all proxies pointing at it.",
                remediation="Confirm reachability and prefer non-destructible implementations.",
            )
        )
    if "DELEGATECALL" in hit_names:
        out.append(
            _child(
                parent=parent,
                step="NEXT",
                title="Next: implementation also uses DELEGATECALL",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description=(
                    f"Implementation {impl} contains DELEGATECALL "
                    f"(count={hit_names['DELEGATECALL']}) — nested proxy / library risk."
                ),
                evidence={"implementation": impl, "count": hit_names["DELEGATECALL"]},
                score_impact=6,
            )
        )

    admin = (parent.evidence or {}).get("admin")
    if admin:
        out.append(
            _child(
                parent=parent,
                step="NEXT",
                title="Next: proxy admin address recorded for review",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description=(
                    f"Proxy admin slot resolves to {admin}. Confirm multisig/timelock, not a hot EOA."
                ),
                evidence={"admin": admin, "implementation": impl},
                score_impact=5,
                remediation="Document admin controls; prefer multisig + timelock for upgrades.",
            )
        )
    return out


def _escalate_selfdestruct(client: RpcClient, parent: Finding, address: str) -> list[Finding]:
    owner, raw = _eth_call_owner(client, address)
    out: list[Finding] = []
    if owner:
        out.append(
            _child(
                parent=parent,
                step="NEXT",
                title=f"Next: owner() returns {owner}",
                severity=Severity.MEDIUM if owner != _ZERO_ADDR else Severity.LOW,
                kind=CheckKind.FINDING,
                description=(
                    "SELFDESTRUCT is present and owner() responds — "
                    "confirm whether destroy paths are owner-gated."
                ),
                evidence={"owner": owner, "raw": _trim(raw)},
                score_impact=8,
                impact="Owner-controlled destruct is a single-key wipe risk.",
                remediation="Verify destroy is unreachable or behind multisig/timelock.",
            )
        )
    else:
        out.append(
            _child(
                parent=parent,
                step="CONFIRM",
                title="Next: owner() not callable (or failed)",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description=(
                    "Could not read owner() after SELFDESTRUCT finding — "
                    "review destroy reachability manually."
                ),
                evidence={"response": _trim(raw)},
                score_impact=0,
            )
        )
    return out


def _escalate_ownable(client: RpcClient, parent: Finding, address: str) -> list[Finding]:
    owner, raw = _eth_call_owner(client, address)
    if not owner:
        return [
            _child(
                parent=parent,
                step="CONFIRM",
                title="Next: Ownable hinted but owner() call failed",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description="Selectors suggested Ownable, but eth_call owner() did not decode.",
                evidence={"response": _trim(raw)},
                score_impact=0,
            )
        ]
    severity = Severity.HIGH if owner != _ZERO_ADDR else Severity.LOW
    return [
        _child(
            parent=parent,
            step="IMPACT",
            title=f"Next: on-chain owner is {owner}",
            severity=severity,
            kind=CheckKind.FINDING,
            description=(
                f"eth_call owner() → {owner}. "
                "Confirm this is a multisig/timelock, not an EOA hot wallet."
            ),
            evidence={"owner": owner, "raw": _trim(raw)},
            score_impact=12 if owner != _ZERO_ADDR else 2,
            impact="Compromised owner keys can upgrade, pause, or drain many protocols.",
            remediation="Move ownership to multisig/timelock and document the address.",
        )
    ]


def _escalate_unverified(
    client: RpcClient, parent: Finding, address: str, context: dict[str, Any]
) -> list[Finding]:
    """Unverified source → try reading owner() and note bytecode size already known."""
    owner, raw = _eth_call_owner(client, address)
    kids = [
        _child(
            parent=parent,
            step="NEXT",
            title="Next: unverified contract — attempted owner() read",
            severity=Severity.LOW if owner else Severity.INFO,
            kind=CheckKind.FINDING if owner else CheckKind.INFO,
            description=(
                f"No Sourcify source; owner() → {owner}."
                if owner
                else "No Sourcify source; owner() not available via eth_call."
            ),
            evidence={"owner": owner, "response": _trim(raw)},
            score_impact=4 if owner else 0,
            remediation="Verify source on Sourcify / explorer for reviewability.",
        )
    ]
    return kids


def run_contract_escalations(
    client: RpcClient,
    *,
    address: str,
    findings: list[Finding],
    context: dict[str, Any] | None = None,
) -> list[Finding]:
    profile = client.limits.name
    if not profile_allows_escalation(profile):
        return []

    budget = max_escalations_for(profile)
    produced: list[Finding] = []
    context = context or {}

    def _take(parent: Finding, kids: list[Finding]) -> None:
        nonlocal produced
        if not kids:
            return
        room = budget - len(produced)
        if room <= 0:
            return
        chunk = kids[:room]
        _mark_parent(parent, chunk)
        produced.extend(chunk)

    for parent in findings:
        if len(produced) >= budget:
            break
        if parent.parent_rule_id:
            continue
        try:
            if parent.rule_id == "SC-PROXY-001" and parent.kind == CheckKind.FINDING:
                _take(parent, _escalate_proxy(client, parent))
            elif parent.rule_id == "SC-BYTE-001" and parent.severity in {
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            }:
                _take(parent, _escalate_selfdestruct(client, parent, address))
            elif parent.rule_id == "SC-IFACE-002":
                _take(parent, _escalate_ownable(client, parent, address))
            elif parent.rule_id == "SC-SRC-001" and parent.kind == CheckKind.FINDING:
                _take(parent, _escalate_unverified(client, parent, address, context))
        except Exception:  # noqa: BLE001
            continue

    return produced
