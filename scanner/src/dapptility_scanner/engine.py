from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from dapptility_scanner import __version__, killswitch
from dapptility_scanner.escalation import run_evm_escalations
from dapptility_scanner.killswitch import KillSwitchActive
from dapptility_scanner.models import CheckKind, ScanError, ScanProfile, ScanResult
from dapptility_scanner.profiles import ProfileLimits, get_profile
from dapptility_scanner.providers import detect_provider
from dapptility_scanner.rpc import BudgetExceeded, RpcClient
from dapptility_scanner.rules import all_rules
from dapptility_scanner.safety import UnsafeTargetError, mask_credentials, validate_target
from dapptility_scanner.scoring import compute_score


class ScannerEngine:
    def __init__(
        self,
        url: str,
        profile: str | ScanProfile | ProfileLimits = "Quick",
        *,
        block_providers: bool = False,
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
        self.block_providers = block_providers
        self.http_client = http_client
        self.skip_tls_probe = skip_tls_probe
        self.resolve_dns = resolve_dns

    def run(self) -> ScanResult:
        started = datetime.now(timezone.utc)
        errors: list[ScanError] = []
        findings = []
        expected = []
        chain_id = None
        network_name = None
        client_version = None
        provider_name = None
        aborted = False
        abort_reason = None
        requests_made = 0

        try:
            killswitch.check()
            provider = detect_provider(self.url)
            if provider:
                provider_name = provider.provider
                if self.block_providers:
                    finished = datetime.now(timezone.utc)
                    return ScanResult(
                        scanner_version=__version__,
                        profile=self.limits.name,
                        endpoint=mask_credentials(self.url),
                        started_at=started.isoformat(),
                        finished_at=finished.isoformat(),
                        duration_ms=int((finished - started).total_seconds() * 1000),
                        requests_made=0,
                        chain_id=None,
                        network_name=None,
                        client_version=None,
                        score=0,
                        findings=[],
                        expected_surface=[],
                        errors=[
                            ScanError(
                                code="third_party_provider",
                                message=(
                                    f"Scan blocked: {provider.reason}. "
                                    "Do not assess provider-hosted RPCs as project-owned infrastructure."
                                ),
                            )
                        ],
                        aborted=True,
                        abort_reason="third_party_provider",
                        provider=provider.provider,
                    )

            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            context: dict[str, Any] = {}

            with RpcClient(target, self.limits, client=self.http_client) as client:
                for rule in all_rules():
                    if self.skip_tls_probe and rule.meta.rule_id == "EVM-TLS-001":
                        continue
                    if not rule.allowed_for(self.limits.name):
                        continue
                    killswitch.check()
                    try:
                        produced = rule.run(client, context)
                    except (BudgetExceeded, KillSwitchActive) as exc:
                        aborted = True
                        abort_reason = str(exc)
                        errors.append(
                            ScanError(code="aborted", message=str(exc))
                        )
                        break
                    except Exception as exc:  # noqa: BLE001 — collect per-rule failures
                        errors.append(
                            ScanError(
                                code="rule_error",
                                message=f"{rule.meta.rule_id}: {exc}",
                            )
                        )
                        continue
                    for item in produced:
                        if item.kind == CheckKind.EXPECTED_SURFACE:
                            expected.append(item)
                        else:
                            findings.append(item)

                # Adaptive escalation: confirm impact of High/Critical namespace hits
                if not aborted:
                    try:
                        killswitch.check()
                        children = run_evm_escalations(client, context, findings)
                        by_parent: dict[str, list[str]] = {}
                        for item in children:
                            if item.parent_rule_id:
                                by_parent.setdefault(item.parent_rule_id, []).append(item.rule_id)
                            if item.kind == CheckKind.EXPECTED_SURFACE:
                                expected.append(item)
                            else:
                                findings.append(item)
                        # Annotate parents so the report shows escalation happened
                        for finding in findings:
                            if finding.rule_id in by_parent and finding.parent_rule_id is None:
                                finding.evidence = {
                                    **(finding.evidence or {}),
                                    "escalation_ran": True,
                                    "escalation_children": by_parent[finding.rule_id],
                                }
                    except (BudgetExceeded, KillSwitchActive) as exc:
                        aborted = True
                        abort_reason = str(exc)
                        errors.append(ScanError(code="aborted", message=str(exc)))
                    except Exception as exc:  # noqa: BLE001
                        errors.append(
                            ScanError(code="escalation_error", message=str(exc))
                        )

                requests_made = client.requests_made
                chain_id = context.get("chain_id")
                network_name = context.get("network_name")
                client_version = context.get("client_version")

        except KillSwitchActive as exc:
            aborted = True
            abort_reason = "kill_switch"
            errors.append(ScanError(code="kill_switch", message=str(exc)))
        except UnsafeTargetError as exc:
            aborted = True
            abort_reason = "unsafe_target"
            errors.append(ScanError(code="unsafe_target", message=str(exc)))
        except Exception as exc:  # noqa: BLE001
            aborted = True
            abort_reason = "scan_error"
            errors.append(ScanError(code="scan_error", message=str(exc)))

        finished = datetime.now(timezone.utc)
        score = 0 if abort_reason in {"unsafe_target", "third_party_provider"} else compute_score(findings)

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
            client_version=client_version,
            score=score,
            findings=findings,
            expected_surface=expected,
            errors=errors,
            aborted=aborted,
            abort_reason=abort_reason,
            provider=provider_name,
        )
