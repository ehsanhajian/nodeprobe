from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

from dapptility_app.config import settings
from dapptility_app.database import (
    AuditLog,
    Endpoint,
    Finding,
    Project,
    Report,
    Scan,
    raw_retention_deadline,
)
from dapptility_app.services.reports import _as_utc, generate_pdf, render_report_html
from dapptility_app.services.scanner import run_scan_for_endpoint
from dapptility_app.services.tokens import new_report_token


def log_action(db: Session, action: str, details: str | None = None, actor: str = "admin") -> None:
    db.add(AuditLog(action=action, actor=actor, details=details))
    db.commit()


def dashboard_stats(db: Session) -> dict:
    return {
        "projects": db.query(func.count(Project.id)).filter(Project.archived.is_(False)).scalar() or 0,
        "scans": db.query(func.count(Scan.id)).scalar() or 0,
        "completed_scans": db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar() or 0,
        "reports": db.query(func.count(Report.id)).scalar() or 0,
        "published_reports": db.query(func.count(Report.id)).filter(Report.status == "published").scalar() or 0,
    }


def create_project(
    db: Session,
    *,
    name: str,
    website: str | None = None,
    network_type: str | None = None,
    project_type: str | None = None,
    launch_stage: str | None = None,
    lead_score: int = 0,
    disclosure_contact: str | None = None,
    communication_notes: str | None = None,
) -> Project:
    project = Project(
        name=name,
        website=website,
        network_type=network_type,
        project_type=project_type,
        launch_stage=launch_stage,
        lead_score=lead_score,
        disclosure_contact=disclosure_contact,
        communication_notes=communication_notes,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    log_action(db, "project.create", f"project_id={project.id}")
    return project


def update_project(db: Session, project: Project, **fields) -> Project:
    for key, value in fields.items():
        if hasattr(project, key) and value is not None:
            setattr(project, key, value)
    db.commit()
    db.refresh(project)
    log_action(db, "project.update", f"project_id={project.id}")
    return project


def add_endpoint(db: Session, project: Project, url: str) -> Endpoint:
    from dapptility_scanner.providers import detect_provider

    provider = detect_provider(url)
    endpoint = Endpoint(
        project_id=project.id,
        url=url,
        is_third_party_provider=provider is not None,
        provider_name=provider.provider if provider else None,
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    log_action(db, "endpoint.create", f"endpoint_id={endpoint.id} project_id={project.id}")
    return endpoint


def execute_scan(db: Session, endpoint: Endpoint, profile: str) -> Scan:
    scan = Scan(
        endpoint_id=endpoint.id,
        profile=profile,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        result = run_scan_for_endpoint(endpoint.url, profile)
        scan.status = "aborted" if result.aborted else "completed"
        scan.score = result.score
        scan.chain_id = result.chain_id
        scan.network_name = result.network_name
        scan.client_version = result.client_version
        scan.requests_made = result.requests_made
        scan.abort_reason = result.abort_reason
        scan.finished_at = datetime.now(timezone.utc)

        raw_path = settings.raw_dir / f"scan-{scan.id}.json"
        raw_path.write_text(json.dumps(result.to_dict(), indent=2))
        scan.raw_result_path = str(raw_path)
        scan.raw_expires_at = raw_retention_deadline()

        for item in result.findings:
            db.add(
                Finding(
                    scan_id=scan.id,
                    rule_id=item.rule_id,
                    title=item.title,
                    category=item.category,
                    severity=item.severity.value,
                    confidence=item.confidence.value,
                    kind=item.kind.value,
                    description=item.description,
                    evidence_json=json.dumps(item.evidence),
                    impact=item.impact,
                    remediation=item.remediation,
                    score_impact=item.score_impact,
                    status="open",
                )
            )
        for item in result.expected_surface:
            db.add(
                Finding(
                    scan_id=scan.id,
                    rule_id=item.rule_id,
                    title=item.title,
                    category=item.category,
                    severity=item.severity.value,
                    confidence=item.confidence.value,
                    kind=item.kind.value,
                    description=item.description,
                    evidence_json=json.dumps(item.evidence),
                    impact=item.impact,
                    remediation=item.remediation,
                    score_impact=0,
                    status="confirmed",
                )
            )
        db.commit()
        log_action(db, "scan.complete", f"scan_id={scan.id} status={scan.status}")
    except Exception as exc:  # noqa: BLE001
        scan.status = "failed"
        scan.abort_reason = "error"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        log_action(db, "scan.failed", f"scan_id={scan.id} error={exc}")
        raise

    db.refresh(scan)
    return scan


def update_finding_status(
    db: Session,
    finding: Finding,
    status: str,
    reviewer_note: str | None = None,
) -> Finding:
    finding.status = status
    if reviewer_note is not None:
        finding.reviewer_note = reviewer_note
    db.commit()
    db.refresh(finding)
    log_action(db, "finding.update", f"finding_id={finding.id} status={status}")
    return finding


def publishable_findings(scan: Scan, profile: str) -> list[Finding]:
    """Outbound requires confirmed findings; others include open findings."""
    findings = [f for f in scan.findings if f.kind != "expected_surface"]
    if profile == "Outbound":
        return [f for f in findings if f.status == "confirmed"]
    return [f for f in findings if f.status in {"open", "confirmed"}]


def create_report_draft(
    db: Session,
    project: Project,
    scan: Scan,
    *,
    title: str,
    report_type: str = "preliminary",
) -> Report:
    report = Report(
        project_id=project.id,
        scan_id=scan.id,
        report_type=report_type,
        title=title,
        token=new_report_token(),
        status="draft",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    log_action(db, "report.create", f"report_id={report.id}")
    return report


def build_and_store_report(db: Session, report: Report) -> Report:
    project = report.project
    scan = report.scan
    endpoint = scan.endpoint
    findings = publishable_findings(scan, scan.profile)

    html = render_report_html(
        project=project,
        endpoint=endpoint,
        scan=scan,
        findings=findings,
        report=report,
    )
    html_path = settings.reports_dir / f"report-{report.id}.html"
    html_path.write_text(html)
    report.html_path = str(html_path)

    pdf_path = settings.reports_dir / f"report-{report.id}.pdf"
    generate_pdf(
        project=project,
        endpoint=endpoint,
        scan=scan,
        findings=findings,
        report=report,
        output_path=pdf_path,
    )
    report.pdf_path = str(pdf_path)
    db.commit()
    db.refresh(report)
    log_action(db, "report.build", f"report_id={report.id}")
    return report


def publish_report(
    db: Session,
    report: Report,
    *,
    expires_at: datetime | None = None,
) -> Report:
    if not report.html_path:
        build_and_store_report(db, report)
    report.status = "published"
    report.published_at = datetime.now(timezone.utc)
    report.expires_at = expires_at
    db.commit()
    db.refresh(report)
    log_action(db, "report.publish", f"report_id={report.id} token={report.token[:8]}...")
    return report


def revoke_report(db: Session, report: Report) -> Report:
    report.status = "revoked"
    db.commit()
    db.refresh(report)
    log_action(db, "report.revoke", f"report_id={report.id}")
    return report


def load_raw_scan(scan: Scan) -> dict | None:
    if not scan.raw_result_path:
        return None
    path = Path(scan.raw_result_path)
    if not path.exists():
        return None
    if scan.raw_expires_at and datetime.now(timezone.utc) > _as_utc(scan.raw_expires_at):
        return None
    return json.loads(path.read_text())


def purge_expired_raw(db: Session) -> int:
    now = datetime.now(timezone.utc)
    expired = db.query(Scan).filter(Scan.raw_expires_at.isnot(None)).all()
    expired = [s for s in expired if _as_utc(s.raw_expires_at) and _as_utc(s.raw_expires_at) < now]
    count = 0
    for scan in expired:
        if scan.raw_result_path:
            path = Path(scan.raw_result_path)
            if path.exists():
                path.unlink()
                count += 1
            scan.raw_result_path = None
    db.commit()
    if count:
        log_action(db, "evidence.purge", f"purged={count}")
    return count
