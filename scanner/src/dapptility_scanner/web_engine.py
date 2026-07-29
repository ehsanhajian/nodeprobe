from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from dapptility_scanner import __version__, killswitch
from dapptility_scanner.http_client import BudgetedHttpClient
from dapptility_scanner.killswitch import KillSwitchActive
from dapptility_scanner.models import CheckKind, ScanError, ScanProfile, ScanResult
from dapptility_scanner.profiles import ProfileLimits, get_profile
from dapptility_scanner.rpc import BudgetExceeded
from dapptility_scanner.rules.web import web_rules
from dapptility_scanner.safety import UnsafeTargetError, mask_credentials, validate_target
from dapptility_scanner.scoring import compute_score


class WebScannerEngine:
    def __init__(
        self,
        url: str,
        profile: str | ScanProfile | ProfileLimits = "Free",
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
        findings = []
        expected = []
        aborted = False
        abort_reason = None
        requests_made = 0

        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            context: dict[str, Any] = {}

            with BudgetedHttpClient(target, self.limits, client=self.http_client) as client:
                # Primary document fetch — shared by header rules
                try:
                    context["primary"] = client.get()
                    if context["primary"].redirect_chain:
                        context["redirect_chain"] = context["primary"].redirect_chain
                except BudgetExceeded as exc:
                    aborted = True
                    abort_reason = str(exc)
                    errors.append(ScanError(code="aborted", message=str(exc)))
                except UnsafeTargetError as exc:
                    aborted = True
                    abort_reason = "unsafe_target"
                    errors.append(ScanError(code="unsafe_target", message=str(exc)))
                else:
                    for rule in web_rules():
                        if self.skip_tls_probe and rule.meta.rule_id == "WEB-TLS-001":
                            continue
                        if not rule.allowed_for(self.limits.name):
                            continue
                        killswitch.check()
                        try:
                            produced = rule.run(client, context)
                        except (BudgetExceeded, KillSwitchActive) as exc:
                            aborted = True
                            abort_reason = str(exc)
                            errors.append(ScanError(code="aborted", message=str(exc)))
                            break
                        except Exception as exc:  # noqa: BLE001
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
                requests_made = client.requests_made

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
        score = (
            0
            if abort_reason in {"unsafe_target", "kill_switch"}
            else compute_score(findings)
        )

        return ScanResult(
            scanner_version=__version__,
            profile=self.limits.name,
            endpoint=mask_credentials(self.url),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            duration_ms=int((finished - started).total_seconds() * 1000),
            requests_made=requests_made,
            chain_id=None,
            network_name=None,
            client_version=None,
            score=score,
            findings=findings,
            expected_surface=expected,
            errors=errors,
            aborted=aborted,
            abort_reason=abort_reason,
            provider=None,
        )
