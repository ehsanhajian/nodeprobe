from __future__ import annotations

import re
from dataclasses import dataclass

from nodeprobe.models import CheckKind, Confidence, Severity
from nodeprobe.rules.base import Rule, RuleMeta


SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS", Severity.MEDIUM, 12),
    ("content-security-policy", "Content-Security-Policy", Severity.MEDIUM, 10),
    ("x-frame-options", "X-Frame-Options", Severity.LOW, 6),
    ("referrer-policy", "Referrer-Policy", Severity.LOW, 4),
    ("permissions-policy", "Permissions-Policy", Severity.LOW, 4),
    ("x-content-type-options", "X-Content-Type-Options", Severity.LOW, 4),
)

# Practical floor: ~180 days. Preload / long-lived HSTS commonly uses 1y+.
_HSTS_WEAK_MAX_AGE = 15_552_000
_HSTS_STRONG_MAX_AGE = 31_536_000


@dataclass(frozen=True)
class PolicyIssue:
    title: str
    severity: Severity
    score_impact: int
    description: str
    impact: str
    remediation: str
    evidence: dict


def grade_hsts(value: str) -> list[PolicyIssue]:
    """Grade an HSTS header value (presence already confirmed)."""
    raw = (value or "").strip()
    lower = raw.lower()
    issues: list[PolicyIssue] = []

    match = re.search(r"max-age\s*=\s*(\d+)", lower)
    max_age = int(match.group(1)) if match else None
    has_sub = "includesubdomains" in lower
    has_preload = "preload" in lower

    if max_age is None:
        issues.append(
            PolicyIssue(
                title="HSTS missing max-age",
                severity=Severity.HIGH,
                score_impact=14,
                description=f"HSTS is set but has no max-age directive: `{raw[:160]}`.",
                impact="Browsers ignore HSTS without max-age, so downgrade protection is ineffective.",
                remediation="Set Strict-Transport-Security with max-age (ideally >= 31536000) and includeSubDomains.",
                evidence={"header": "strict-transport-security", "value": raw[:200], "issue": "missing_max_age"},
            )
        )
    elif max_age < _HSTS_WEAK_MAX_AGE:
        issues.append(
            PolicyIssue(
                title="HSTS max-age is too short",
                severity=Severity.MEDIUM,
                score_impact=10,
                description=(
                    f"HSTS max-age={max_age} is below {_HSTS_WEAK_MAX_AGE} "
                    f"(~180 days). Value: `{raw[:160]}`."
                ),
                impact="Short HSTS lifetimes leave users unprotected after expiry and weaken preload eligibility.",
                remediation=(
                    f"Raise max-age to at least {_HSTS_WEAK_MAX_AGE}; "
                    f"{_HSTS_STRONG_MAX_AGE} (1 year) is preferred for preload."
                ),
                evidence={
                    "header": "strict-transport-security",
                    "value": raw[:200],
                    "max_age": max_age,
                    "issue": "weak_max_age",
                },
            )
        )
    elif max_age < _HSTS_STRONG_MAX_AGE:
        issues.append(
            PolicyIssue(
                title="HSTS max-age below one-year recommendation",
                severity=Severity.LOW,
                score_impact=4,
                description=(
                    f"HSTS max-age={max_age} works but is below the common "
                    f"{_HSTS_STRONG_MAX_AGE} (1 year) / preload recommendation."
                ),
                impact="Shorter lifetimes are valid but less durable for first-visit and preload readiness.",
                remediation=f"Consider max-age={_HSTS_STRONG_MAX_AGE} with includeSubDomains when ready for preload.",
                evidence={
                    "header": "strict-transport-security",
                    "value": raw[:200],
                    "max_age": max_age,
                    "issue": "suboptimal_max_age",
                },
            )
        )

    if max_age is not None and not has_sub:
        issues.append(
            PolicyIssue(
                title="HSTS missing includeSubDomains",
                severity=Severity.LOW,
                score_impact=5,
                description=f"HSTS does not set includeSubDomains: `{raw[:160]}`.",
                impact="Subdomains remain reachable over cleartext HTTP and are outside HSTS protection.",
                remediation="Add includeSubDomains once all subdomains speak HTTPS.",
                evidence={
                    "header": "strict-transport-security",
                    "value": raw[:200],
                    "issue": "missing_includesubdomains",
                },
            )
        )

    if has_preload and (not has_sub or max_age is None or max_age < _HSTS_STRONG_MAX_AGE):
        issues.append(
            PolicyIssue(
                title="HSTS preload token without preload-ready policy",
                severity=Severity.MEDIUM,
                score_impact=8,
                description=(
                    "preload is present but policy is not preload-ready "
                    "(needs includeSubDomains and max-age >= 31536000)."
                ),
                impact="preload without a qualifying policy is ignored by the preload list and confuses operators.",
                remediation="Use max-age=31536000; includeSubDomains; preload only when every subdomain is HTTPS.",
                evidence={
                    "header": "strict-transport-security",
                    "value": raw[:200],
                    "max_age": max_age,
                    "includeSubDomains": has_sub,
                    "preload": has_preload,
                    "issue": "preload_not_ready",
                },
            )
        )

    return issues


def _csp_directives(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, rest = part.partition(" ")
        out[name.lower()] = rest.strip()
    return out


def _source_list(directives: dict[str, str], name: str) -> str:
    if name in directives:
        return directives[name]
    if name != "default-src":
        return directives.get("default-src", "")
    return ""


def grade_csp(value: str, *, has_xfo: bool = False) -> list[PolicyIssue]:
    """Grade a Content-Security-Policy header value (presence already confirmed)."""
    raw = (value or "").strip()
    directives = _csp_directives(raw)
    issues: list[PolicyIssue] = []

    script_src = _source_list(directives, "script-src").lower()
    default_src = directives.get("default-src", "").lower()
    object_src = _source_list(directives, "object-src").lower()
    frame_ancestors = directives.get("frame-ancestors", "").lower()

    if "unsafe-inline" in script_src or (
        "script-src" not in directives and "unsafe-inline" in default_src
    ):
        issues.append(
            PolicyIssue(
                title="CSP allows unsafe-inline scripts",
                severity=Severity.HIGH,
                score_impact=14,
                description=(
                    "CSP script policy includes 'unsafe-inline', which weakens XSS containment. "
                    f"Policy snippet: `{raw[:180]}`."
                ),
                impact="Inline script execution largely defeats CSP as an XSS mitigation.",
                remediation="Remove 'unsafe-inline'; prefer nonces or hashes for trusted scripts.",
                evidence={
                    "header": "content-security-policy",
                    "value": raw[:300],
                    "issue": "unsafe_inline",
                    "directive": "script-src" if "script-src" in directives else "default-src",
                },
            )
        )

    if "unsafe-eval" in script_src or (
        "script-src" not in directives and "unsafe-eval" in default_src
    ):
        issues.append(
            PolicyIssue(
                title="CSP allows unsafe-eval",
                severity=Severity.MEDIUM,
                score_impact=10,
                description=(
                    "CSP script policy includes 'unsafe-eval' (eval/new Function). "
                    f"Policy snippet: `{raw[:180]}`."
                ),
                impact="Eval-style APIs expand XSS impact when an injection lands.",
                remediation="Remove 'unsafe-eval' and avoid runtime code generation in the browser.",
                evidence={
                    "header": "content-security-policy",
                    "value": raw[:300],
                    "issue": "unsafe_eval",
                },
            )
        )

    for directive, sources, severity, impact_pts in (
        ("script-src", script_src, Severity.HIGH, 14),
        ("default-src", default_src, Severity.HIGH, 12),
        ("object-src", object_src, Severity.MEDIUM, 8),
        ("frame-ancestors", frame_ancestors, Severity.MEDIUM, 8),
    ):
        tokens = sources.split()
        if "*" in tokens or "https:" in tokens or "http:" in tokens:
            wildcard = "*" if "*" in tokens else ("https:" if "https:" in tokens else "http:")
            issues.append(
                PolicyIssue(
                    title=f"CSP {directive} is overly broad ({wildcard})",
                    severity=severity,
                    score_impact=impact_pts,
                    description=(
                        f"CSP `{directive}` allows `{wildcard}`, which is too permissive. "
                        f"Policy snippet: `{raw[:180]}`."
                    ),
                    impact="Broad source lists let untrusted origins supply scripts, plugins, or frames.",
                    remediation=f"Tighten `{directive}` to explicit trusted hosts; avoid * / scheme-only sources.",
                    evidence={
                        "header": "content-security-policy",
                        "value": raw[:300],
                        "issue": "wildcard_source",
                        "directive": directive,
                        "token": wildcard,
                    },
                )
            )

    if "data:" in script_src or (
        "script-src" not in directives and "data:" in default_src
    ):
        issues.append(
            PolicyIssue(
                title="CSP allows data: scripts",
                severity=Severity.MEDIUM,
                score_impact=8,
                description="CSP script policy allows data: URIs, which can enable script smuggling.",
                impact="data: script sources bypass host allowlists and aid XSS exploitation.",
                remediation="Remove data: from script-src / default-src.",
                evidence={
                    "header": "content-security-policy",
                    "value": raw[:300],
                    "issue": "data_script",
                },
            )
        )

    if "frame-ancestors" not in directives and not has_xfo:
        issues.append(
            PolicyIssue(
                title="CSP missing frame-ancestors (and no X-Frame-Options)",
                severity=Severity.MEDIUM,
                score_impact=8,
                description=(
                    "CSP is present but does not set frame-ancestors, and X-Frame-Options "
                    "is also absent — clickjacking controls are incomplete."
                ),
                impact="Third parties can frame the page.",
                remediation="Add CSP frame-ancestors 'none'/'self' or X-Frame-Options: DENY/SAMEORIGIN.",
                evidence={
                    "header": "content-security-policy",
                    "value": raw[:300],
                    "issue": "missing_frame_ancestors",
                    "x_frame_options": False,
                },
            )
        )
    elif "frame-ancestors" not in directives and has_xfo:
        issues.append(
            PolicyIssue(
                title="CSP missing frame-ancestors (X-Frame-Options present)",
                severity=Severity.LOW,
                score_impact=3,
                description=(
                    "Framing is constrained via X-Frame-Options, but CSP has no frame-ancestors. "
                    "Prefer CSP for modern browsers."
                ),
                impact="XFO works in many browsers; CSP frame-ancestors is the modern control.",
                remediation="Add frame-ancestors to CSP and keep or retire X-Frame-Options deliberately.",
                evidence={
                    "header": "content-security-policy",
                    "value": raw[:300],
                    "issue": "missing_frame_ancestors_xfo_ok",
                    "x_frame_options": True,
                },
            )
        )

    return issues


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


class WeakHstsRule(Rule):
    meta = RuleMeta(
        rule_id="WEB-HDR-003",
        title="Weak HSTS policy",
        description="Grade HSTS when present: max-age, includeSubDomains, preload readiness.",
        category="HTTP Security",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Weak HSTS policies leave first-visit and subdomain downgrade paths open.",
        remediation="Use a long max-age, includeSubDomains when safe, and preload only when ready.",
        score_impact=8,
    )

    def run(self, client, context):
        exchange = context.get("primary") or client.get()
        context["primary"] = exchange
        value = exchange.headers.get("strict-transport-security")
        if not value:
            return []
        findings = []
        for issue in grade_hsts(value):
            findings.append(
                self.finding(
                    title=issue.title,
                    severity=issue.severity,
                    score_impact=issue.score_impact,
                    description=issue.description,
                    impact=issue.impact,
                    remediation=issue.remediation,
                    evidence={**issue.evidence, "url": exchange.final_url},
                )
            )
        if not findings:
            findings.append(
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    score_impact=0,
                    title="HSTS policy looks solid",
                    description=f"HSTS directives look reasonable: `{value[:160]}`.",
                    evidence={"header": "strict-transport-security", "value": value[:200]},
                )
            )
        return findings


class WeakCspRule(Rule):
    meta = RuleMeta(
        rule_id="WEB-HDR-004",
        title="Weak CSP policy",
        description=(
            "Grade Content-Security-Policy when present: unsafe-inline/eval, wildcards, "
            "frame-ancestors."
        ),
        category="HTTP Security",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Weak CSP policies fail to contain XSS and clickjacking.",
        remediation="Tighten script-src, remove unsafe-* / wildcards, and set frame-ancestors.",
        score_impact=10,
    )

    def run(self, client, context):
        exchange = context.get("primary") or client.get()
        context["primary"] = exchange
        value = exchange.headers.get("content-security-policy")
        if not value:
            return []
        has_xfo = bool(exchange.headers.get("x-frame-options"))
        findings = []
        for issue in grade_csp(value, has_xfo=has_xfo):
            findings.append(
                self.finding(
                    title=issue.title,
                    severity=issue.severity,
                    score_impact=issue.score_impact,
                    description=issue.description,
                    impact=issue.impact,
                    remediation=issue.remediation,
                    evidence={**issue.evidence, "url": exchange.final_url},
                )
            )
        if not findings:
            findings.append(
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    score_impact=0,
                    title="CSP policy looks reasonably strict",
                    description=f"No common CSP weakness patterns detected: `{value[:160]}`.",
                    evidence={"header": "content-security-policy", "value": value[:300]},
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
