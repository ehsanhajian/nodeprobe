"""Generate outreach email drafts from scan results."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from dapptility_app.config import settings
from dapptility_app.database import Finding, Project, Report, Scan


@dataclass
class EmailDraft:
    subject: str
    body: str
    finding_count: int
    has_critical: bool
    report_url: str | None = None


def _severity_order(sev: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(sev, 5)


def _report_public_url(report: Report) -> str:
    return f"{settings.report_base_url.rstrip('/')}/r/{report.token}"


def generate_outreach_email(
    db: Session,
    project: Project,
    scan: Scan,
    *,
    report: Report | None = None,
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

    severities: dict[str, int] = {}
    for f in findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1
    severity_summary = ", ".join(f"{count} {sev}" for sev, count in severities.items())

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

    report_url = _report_public_url(report) if report and report.status == "published" else None

    if report_url:
        report_section = f"""

We've prepared a preliminary report with evidence and remediation guidance:
{report_url}
"""
        follow_up = "We can also run a comprehensive authorized assessment if you're interested."
    else:
        report_section = ""
        follow_up = (
            "We'd be happy to share a detailed report with evidence and remediation guidance"
            f"{' — given the severity, we recommend addressing these promptly' if has_critical else ''}. "
            "We can also run a comprehensive authorized assessment if you're interested."
        )

    body = f"""Hi {project.name} team,

I'm reaching out because we ran a non-intrusive security assessment of your public JSON-RPC endpoint at {endpoint_url}{chain_info} and found {len(findings)} issue(s) worth your attention ({severity_summary}).

Key findings:

{chr(10).join(finding_bullets)}

This was a limited scan using only standard read-only JSON-RPC calls — no writes, no state changes, no privileged operations. We believe these findings represent real exposure that could affect your users or infrastructure.
{report_section}
{follow_up}

Would you have 15 minutes this week to discuss?

Best regards,
Dapptility Security Team
https://dapptility.com"""

    return EmailDraft(
        subject=subject,
        body=body,
        finding_count=len(findings),
        has_critical=has_critical,
        report_url=report_url,
    )
