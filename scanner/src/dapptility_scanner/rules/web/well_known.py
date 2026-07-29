from __future__ import annotations

from dapptility_scanner.models import CheckKind, Confidence, Severity
from dapptility_scanner.rules.base import Rule, RuleMeta


class SecurityTxtRule(Rule):
    meta = RuleMeta(
        rule_id="WEB-WKN-001",
        title="security.txt presence",
        description="Check for RFC 9116 security.txt at /.well-known/security.txt.",
        category="Disclosure",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        impact="Without security.txt, researchers may lack a clear disclosure channel.",
        remediation="Publish /.well-known/security.txt with Contact and Preferred-Languages fields.",
        score_impact=4,
        references=["https://www.rfc-editor.org/rfc/rfc9116"],
    )

    def run(self, client, context):
        exchange = client.get("/.well-known/security.txt")
        context["security_txt"] = {
            "status": exchange.status_code,
            "url": exchange.final_url,
        }
        if exchange.status_code == 200 and exchange.body_text.strip():
            body = exchange.body_text[:2000]
            has_contact = "contact:" in body.lower()
            return [
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    score_impact=0,
                    evidence={
                        "status": exchange.status_code,
                        "has_contact": has_contact,
                        "snippet": body[:400],
                    },
                    description="security.txt is present"
                    + (" and includes Contact." if has_contact else " but Contact field was not found."),
                )
            ]
        # Fallback path used by some hosts
        fallback = client.get("/security.txt")
        if fallback.status_code == 200 and fallback.body_text.strip():
            return [
                self.finding(
                    kind=CheckKind.EXPECTED_SURFACE,
                    severity=Severity.INFO,
                    score_impact=0,
                    evidence={"status": fallback.status_code, "url": fallback.final_url},
                    description="security.txt found at /security.txt (prefer /.well-known/security.txt).",
                )
            ]
        return [
            self.finding(
                evidence={"well_known_status": exchange.status_code, "fallback_status": fallback.status_code},
                description="No security.txt found at /.well-known/security.txt or /security.txt.",
            )
        ]


class RobotsTxtRule(Rule):
    meta = RuleMeta(
        rule_id="WEB-WKN-002",
        title="robots.txt observation",
        description="Fetch robots.txt for inventory / sensitive path hints.",
        category="Disclosure",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.INFO,
        impact="robots.txt can reveal admin or internal paths.",
        remediation="Avoid listing sensitive paths; keep robots.txt minimal.",
        score_impact=0,
    )

    def run(self, client, context):
        exchange = client.get("/robots.txt")
        context["robots_txt"] = {"status": exchange.status_code}
        if exchange.status_code != 200:
            return [
                self.finding(
                    kind=CheckKind.INFO,
                    evidence={"status": exchange.status_code},
                    description="robots.txt was not returned (not necessarily a finding).",
                )
            ]
        body = exchange.body_text[:4000]
        interesting = [
            line.strip()
            for line in body.splitlines()
            if line.strip().lower().startswith("disallow:")
            and any(
                token in line.lower()
                for token in ("admin", "login", "api", "internal", "private", "debug")
            )
        ]
        if interesting:
            return [
                self.finding(
                    title="robots.txt lists potentially sensitive paths",
                    severity=Severity.LOW,
                    kind=CheckKind.FINDING,
                    score_impact=3,
                    evidence={"disallow_hints": interesting[:20]},
                    description="robots.txt Disallow entries mention potentially sensitive paths.",
                )
            ]
        return [
            self.finding(
                kind=CheckKind.INFO,
                evidence={"bytes": len(body)},
                description="robots.txt present; no obvious sensitive Disallow hints.",
            )
        ]
