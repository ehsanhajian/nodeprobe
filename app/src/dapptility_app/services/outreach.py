"""Generate outreach email drafts from scan results."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from dapptility_app.database import Finding, Project, Scan


@dataclass
class EmailDraft:
    subject: str
    body: str
    finding_count: int
    has_critical: bool


def _severity_order(sev: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(sev, 5)


def generate_outreach_email(
    db: Session,
    project: Project,
    scan: Scan,
) -> EmailDraft | None:
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id,
            Finding.kind != "expected_surface",
            Finding.status.in_(["open", "confirmed"]),
        )
        .all()
    )

    if not findings:
        return None

    findings.sort(key=lambda f: _severity_order(f.severity))

    severities = {}
    for f in findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1
    severity_summary = ", ".join(
        f"{count} {sev}" for sev, count in severities.items()
    )

    has_critical = any(f.severity in ("Critical", "High") for f in findings)

    subject = f"Security findings on your {project.name} RPC endpoint"

    finding_bullets = []
    for f in findings[:5]:
        bullet = f"  • [{f.severity}] {f.title}"
        if f.impact:
            bullet += f" — {f.impact}"
        finding_bullets.append(bullet)
    if len(findings) > 5:
        finding_bullets.append(f"  • ...and {len(findings) - 5} more finding(s)")

    endpoint_url = scan.endpoint.url if scan.endpoint else "your RPC endpoint"
    chain_info = f" ({scan.network_name})" if scan.network_name else ""

    body = f"""Hi {project.name} team,

I'm reaching out because we ran a non-intrusive security assessment of your public JSON-RPC endpoint at {endpoint_url}{chain_info} and found {len(findings)} issue(s) worth your attention ({severity_summary}).

Key findings:

{chr(10).join(finding_bullets)}

This was a limited scan using only standard read-only JSON-RPC calls — no writes, no state changes, no privileged operations. We believe these findings represent real exposure that could affect your users or infrastructure.

We'd be happy to share a detailed report with evidence and remediation guidance{"  — given the severity, we recommend addressing these promptly" if has_critical else ""}. We can also run a comprehensive authorized assessment if you're interested.

Would you have 15 minutes this week to discuss?

Best regards,
Dapptility Security Team
https://dapptility.com"""

    return EmailDraft(
        subject=subject,
        body=body,
        finding_count=len(findings),
        has_critical=has_critical,
    )
