"""Read-only smart contract surface scanner via JSON-RPC (+ optional Sourcify)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx

from dapptility_scanner import __version__, killswitch
from dapptility_scanner.chains import resolve_chain
from dapptility_scanner.contract import (
    analyze_bytecode,
    detect_eip1167,
    detect_proxies_from_slots,
    extract_selectors,
    fetch_sourcify,
    interfaces_from_abi,
    interfaces_from_selectors,
    is_empty_code,
    normalize_address,
)
from dapptility_scanner.escalation_contract import run_contract_escalations
from dapptility_scanner.killswitch import KillSwitchActive
from dapptility_scanner.models import (
    CheckKind,
    Confidence,
    Finding,
    ScanError,
    ScanProfile,
    ScanResult,
    Severity,
)
from dapptility_scanner.profiles import ProfileLimits, get_profile
from dapptility_scanner.rpc import BudgetExceeded, RpcClient
from dapptility_scanner.safety import UnsafeTargetError, mask_credentials, validate_target
from dapptility_scanner.scoring import compute_score


def _finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    confidence: Confidence,
    kind: CheckKind,
    description: str,
    evidence: dict[str, Any] | None = None,
    impact: str = "",
    remediation: str = "",
    score_impact: int = 0,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        kind=kind,
        description=description,
        evidence=evidence or {},
        impact=impact,
        remediation=remediation,
        score_impact=score_impact,
    )


class ContractScannerEngine:
    def __init__(
        self,
        address: str,
        *,
        rpc_url: str,
        chain_id: int | None = None,
        profile: str | ScanProfile | ProfileLimits = "Quick",
        abi_json: str | list | None = None,
        fetch_verification: bool = True,
        http_client: httpx.Client | None = None,
        resolve_dns: bool = True,
    ):
        if isinstance(profile, ProfileLimits):
            self.limits = profile
        elif isinstance(profile, ScanProfile):
            self.limits = get_profile(profile.value)
        else:
            self.limits = get_profile(profile)
        self.address = normalize_address(address)
        self.rpc_url = rpc_url
        self.chain_id_hint = chain_id
        self.fetch_verification = fetch_verification
        self.http_client = http_client
        self.resolve_dns = resolve_dns
        self.abi: list[dict[str, Any]] | None = None
        if isinstance(abi_json, list):
            self.abi = abi_json
        elif isinstance(abi_json, str) and abi_json.strip():
            try:
                parsed = json.loads(abi_json)
                if isinstance(parsed, list):
                    self.abi = parsed
            except json.JSONDecodeError:
                self.abi = None

    def run(self) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[ScanError] = []
        findings: list[Finding] = []
        expected: list[Finding] = []
        aborted = False
        abort_reason = None
        requests_made = 0
        chain_id: int | None = self.chain_id_hint
        network_name: str | None = None

        try:
            killswitch.check()
            target = validate_target(self.rpc_url, resolve_dns=self.resolve_dns)

            with RpcClient(target, self.limits, client=self.http_client) as client:
                # Resolve chain
                try:
                    remote_chain = client.call("eth_chainId")
                    if isinstance(remote_chain, str):
                        remote_id = int(remote_chain, 16)
                    elif isinstance(remote_chain, int):
                        remote_id = remote_chain
                    else:
                        remote_id = None
                    if remote_id is not None:
                        if chain_id is not None and remote_id != chain_id:
                            findings.append(
                                _finding(
                                    rule_id="SC-IDENT-001",
                                    title="RPC chain ID mismatch",
                                    category="Identity",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"Provided chain_id={chain_id} but RPC reports {remote_id}."
                                    ),
                                    evidence={"provided": chain_id, "rpc": remote_id},
                                    impact="Findings may describe the wrong network.",
                                    remediation="Point --rpc at an endpoint for the intended chain.",
                                    score_impact=15,
                                )
                            )
                        chain_id = remote_id
                except Exception as exc:  # noqa: BLE001
                    errors.append(ScanError(code="chain_id", message=str(exc)))

                if chain_id is not None:
                    info = resolve_chain(chain_id)
                    network_name = info.name
                    if not info.listed:
                        findings.append(
                            _finding(
                                rule_id="SC-IDENT-002",
                                title="Chain not in local name registry",
                                category="Identity",
                                severity=Severity.INFO,
                                confidence=Confidence.CONFIRMED,
                                kind=CheckKind.INFO,
                                description=(
                                    f"Chain {chain_id} has no entry in the bundled Chainlist "
                                    "snapshot; continuing read-only checks anyway."
                                ),
                                evidence={"chain_id": chain_id},
                            )
                        )

                code = client.call("eth_getCode", [self.address, "latest"])
                code_hex = code if isinstance(code, str) else "0x"
                context_code_len = max(0, (len(code_hex) - 2) // 2)

                if is_empty_code(code_hex):
                    findings.append(
                        _finding(
                            rule_id="SC-CODE-001",
                            title="Address has no contract code (EOA or empty)",
                            category="Code",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            kind=CheckKind.FINDING,
                            description=(
                                f"{self.address} returned empty code via eth_getCode. "
                                "Not a deployed contract at this block."
                            ),
                            evidence={"address": self.address, "code": "0x"},
                            impact="Further bytecode / proxy analysis does not apply.",
                            remediation="Confirm address, chain, and deployment status.",
                            score_impact=8,
                        )
                    )
                else:
                    expected.append(
                        _finding(
                            rule_id="SC-CODE-001",
                            title="Contract bytecode present",
                            category="Code",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            kind=CheckKind.EXPECTED_SURFACE,
                            description=f"eth_getCode returned {context_code_len} bytes.",
                            evidence={"address": self.address, "code_bytes": context_code_len},
                        )
                    )

                    # EIP-1167 from bytecode
                    eip1167 = detect_eip1167(code_hex)
                    proxy_hints = []
                    if eip1167:
                        proxy_hints.append(eip1167)

                    def _storage(slot: str) -> str | None:
                        try:
                            value = client.call("eth_getStorageAt", [self.address, slot, "latest"])
                            return value if isinstance(value, str) else None
                        except Exception:  # noqa: BLE001
                            return None

                    proxy_hints.extend(detect_proxies_from_slots(get_storage=_storage))

                    if proxy_hints:
                        for hint in proxy_hints:
                            findings.append(
                                _finding(
                                    rule_id="SC-PROXY-001",
                                    title=f"Proxy pattern detected ({hint.kind})",
                                    category="Proxy",
                                    severity=Severity.INFO,
                                    confidence=Confidence.LIKELY,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"Address appears to be a {hint.kind} proxy"
                                        + (
                                            f" → implementation {hint.implementation}"
                                            if hint.implementation
                                            else ""
                                        )
                                        + (f", admin {hint.admin}" if hint.admin else "")
                                        + "."
                                    ),
                                    evidence={
                                        "kind": hint.kind,
                                        "implementation": hint.implementation,
                                        "admin": hint.admin,
                                        "beacon": hint.beacon,
                                        **(hint.evidence or {}),
                                    },
                                    impact="Upgrades and admin keys dominate risk for proxy systems.",
                                    remediation=(
                                        "Verify implementation address, admin/owner controls, "
                                        "and upgrade timelock / multisig posture."
                                    ),
                                    score_impact=2,
                                )
                            )
                    else:
                        expected.append(
                            _finding(
                                rule_id="SC-PROXY-001",
                                title="No common proxy slots/patterns detected",
                                category="Proxy",
                                severity=Severity.INFO,
                                confidence=Confidence.LIKELY,
                                kind=CheckKind.EXPECTED_SURFACE,
                                description="No EIP-1967/1822 slots or EIP-1167 bytecode pattern found.",
                                evidence={"address": self.address},
                            )
                        )

                    # Bytecode heuristics
                    hits = analyze_bytecode(code_hex)
                    for hit in hits:
                        if hit.name == "SELFDESTRUCT":
                            findings.append(
                                _finding(
                                    rule_id="SC-BYTE-001",
                                    title="SELFDESTRUCT opcode present in bytecode",
                                    category="Bytecode",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.LIKELY,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"Bytecode contains SELFDESTRUCT (count={hit.count}). "
                                        "May be unreachable; confirm with source/review."
                                    ),
                                    evidence={"opcode": hit.opcode, "count": hit.count},
                                    impact="Destructible contracts can wipe code and send funds.",
                                    remediation="Prefer non-destructible designs; verify reachability.",
                                    score_impact=12,
                                )
                            )
                        elif hit.name == "DELEGATECALL":
                            findings.append(
                                _finding(
                                    rule_id="SC-BYTE-002",
                                    title="DELEGATECALL opcode present in bytecode",
                                    category="Bytecode",
                                    severity=Severity.LOW,
                                    confidence=Confidence.CONFIRMED,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        f"Bytecode contains DELEGATECALL (count={hit.count}). "
                                        "Expected for many proxies; review callee controls."
                                    ),
                                    evidence={"opcode": hit.opcode, "count": hit.count},
                                    impact="Unsafe DELEGATECALL targets can fully compromise storage.",
                                    remediation="Ensure delegate targets are trusted and upgrade-controlled.",
                                    score_impact=4,
                                )
                            )

                    selectors = extract_selectors(code_hex)
                    iface_sel = interfaces_from_selectors(selectors)

                    # Sourcify enrichment
                    abi = self.abi
                    if self.fetch_verification and chain_id is not None:
                        match = fetch_sourcify(
                            chain_id,
                            self.address,
                            client=self.http_client,
                        )
                        if match.status in {"exact_match", "match", "partial"}:
                            expected.append(
                                _finding(
                                    rule_id="SC-SRC-001",
                                    title=f"Sourcify verification ({match.status})",
                                    category="Source",
                                    severity=Severity.INFO,
                                    confidence=Confidence.CONFIRMED,
                                    kind=CheckKind.EXPECTED_SURFACE,
                                    description=(
                                        f"Sourcify reports {match.status}"
                                        + (f" for {match.contract_name}" if match.contract_name else "")
                                        + (f" (compiler {match.compiler})" if match.compiler else "")
                                        + "."
                                    ),
                                    evidence={
                                        "status": match.status,
                                        "contract_name": match.contract_name,
                                        "compiler": match.compiler,
                                        "has_abi": bool(match.abi),
                                    },
                                )
                            )
                            if match.abi and not abi:
                                abi = match.abi
                        elif match.status == "not_found":
                            findings.append(
                                _finding(
                                    rule_id="SC-SRC-001",
                                    title="No Sourcify verification found",
                                    category="Source",
                                    severity=Severity.LOW,
                                    confidence=Confidence.CONFIRMED,
                                    kind=CheckKind.FINDING,
                                    description="Contract is not verified on Sourcify for this chain/address.",
                                    evidence={"chain_id": chain_id, "address": self.address},
                                    impact="Harder to review logic without verified source.",
                                    remediation="Publish verified source to Sourcify or an explorer.",
                                    score_impact=3,
                                )
                            )
                        else:
                            errors.append(
                                ScanError(
                                    code="sourcify",
                                    message=f"Sourcify lookup failed: {match.raw}",
                                )
                            )

                    iface_abi = interfaces_from_abi(abi)
                    interfaces = sorted(set(iface_sel) | set(iface_abi))
                    if interfaces:
                        expected.append(
                            _finding(
                                rule_id="SC-IFACE-001",
                                title="Interface hints",
                                category="Interfaces",
                                severity=Severity.INFO,
                                confidence=Confidence.LIKELY,
                                kind=CheckKind.EXPECTED_SURFACE,
                                description="Detected interface hints: " + ", ".join(interfaces),
                                evidence={
                                    "interfaces": interfaces,
                                    "from_selectors": iface_sel,
                                    "from_abi": iface_abi,
                                },
                            )
                        )
                        if "Ownable" in interfaces and "AccessControl" not in interfaces:
                            findings.append(
                                _finding(
                                    rule_id="SC-IFACE-002",
                                    title="Ownable-style ownership surface",
                                    category="Access Control",
                                    severity=Severity.INFO,
                                    confidence=Confidence.LIKELY,
                                    kind=CheckKind.FINDING,
                                    description=(
                                        "Selectors/ABI suggest Ownable. Confirm owner is a multisig "
                                        "or timelock, not a hot EOA."
                                    ),
                                    evidence={"interfaces": interfaces},
                                    impact="Single-key owners are a common compromise path.",
                                    remediation="Use multisig/timelock; document owner address.",
                                    score_impact=2,
                                )
                            )

                if not aborted:
                    try:
                        killswitch.check()
                        for item in run_contract_escalations(
                            client,
                            address=self.address,
                            findings=findings,
                        ):
                            if item.kind == CheckKind.EXPECTED_SURFACE:
                                expected.append(item)
                            else:
                                findings.append(item)
                    except (BudgetExceeded, KillSwitchActive) as exc:
                        aborted = True
                        abort_reason = str(exc)
                        errors.append(ScanError(code="aborted", message=str(exc)))
                    except Exception as exc:  # noqa: BLE001
                        errors.append(
                            ScanError(code="escalation_error", message=str(exc))
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
        except ValueError as exc:
            aborted = True
            abort_reason = "invalid_address"
            errors.append(ScanError(code="invalid_address", message=str(exc)))
        except BudgetExceeded as exc:
            aborted = True
            abort_reason = str(exc)
            errors.append(ScanError(code="aborted", message=str(exc)))
        except Exception as exc:  # noqa: BLE001
            aborted = True
            abort_reason = "scan_error"
            errors.append(ScanError(code="scan_error", message=str(exc)))

        finished = datetime.now(timezone.utc)
        score = (
            0
            if abort_reason in {"unsafe_target", "kill_switch", "invalid_address"}
            else compute_score(findings)
        )

        return ScanResult(
            scanner_version=__version__,
            profile=self.limits.name,
            endpoint=f"{self.address}@{mask_credentials(self.rpc_url)}",
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_ms=int((finished - started).total_seconds() * 1000),
            requests_made=requests_made,
            chain_id=chain_id,
            network_name=network_name,
            client_version=None,
            score=score,
            findings=findings,
            expected_surface=expected,
            errors=errors,
            aborted=aborted,
            abort_reason=abort_reason,
            provider=None,
        )
