from __future__ import annotations

from dapptility_scanner.models import CheckKind, Confidence, Severity
from dapptility_scanner.rules.base import Rule, RuleMeta


SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS", Severity.MEDIUM, 12),
    ("content-security-policy", "Content-Security-Policy", Severity.MEDIUM, 10),
    ("x-frame-options", "X-Frame-Options", Severity.LOW, 6),
    ("referrer-policy", "Referrer-Policy", Severity.LOW, 4),
    ("permissions-policy", "Permissions-Policy", Severity.LOW, 4),
    ("x-content-type-options", "X-Content-Type-Options", Severity.LOW, 4),
)


class SecurityHeadersRule(Rule):
    meta = RuleMeta(
        rule_id="WEB-HDR-001",
        title="Missing security headers",
        description="Check common browser security headers on the primary response.",
        category="HTTP Security",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Missing headers increase risk of clickjacking, XSS amplification, and downgrade attacks.",
        remediation=(
            "Set HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, "
            "and frame controls (CSP frame-ancestors or X-Frame-Options)."
        ),
        score_impact=10,
    )

    def run(self, client, context):
        exchange = context.get("primary") or client.get()
        context["primary"] = exchange
        headers = exchange.headers
        findings = []
        present = []
        missing = []

        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        for header, label, severity, impact in SECURITY_HEADERS:
            if header == "x-frame-options" and has_frame_ancestors:
                present.append(f"{label} (via CSP frame-ancestors)")
                continue
            value = headers.get(header)
            if value:
                present.append(f"{label}: {value[:120]}")
            else:
                missing.append(label)
                findings.append(
                    self.finding(
                        title=f"Missing {label} header",
                        severity=severity,
                        score_impact=impact,
                        evidence={"header": header, "url": exchange.final_url},
                        description=f"Response from {exchange.final_url} does not include {label}.",
                    )
                )

        context["security_headers"] = {"present": present, "missing": missing}
        if not missing:
            findings.append(
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    score_impact=0,
                    evidence={"present": present},
                    description="Core security headers are present.",
                )
            )
        return findings


class ServerDisclosureRule(Rule):
    meta = RuleMeta(
        rule_id="WEB-HDR-002",
        title="Server / technology disclosure",
        description="Flag Server and X-Powered-By response headers.",
        category="HTTP Security",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Versioned server banners help attackers target known CVEs.",
        remediation="Remove or genericize Server and X-Powered-By headers at the edge.",
        score_impact=2,
    )

    def run(self, client, context):
        exchange = context.get("primary") or client.get()
        context["primary"] = exchange
        findings = []
        for header in ("server", "x-powered-by"):
            value = exchange.headers.get(header)
            if value:
                findings.append(
                    self.finding(
                        title=f"{header} header discloses technology",
                        evidence={"header": header, "value": value},
                        description=f"Response includes `{header}: {value}`.",
                    )
                )
        return findings
