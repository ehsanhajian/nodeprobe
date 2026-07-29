from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from dapptility_app.config import settings
from dapptility_app.database import (
    AuditLog,
    DiscoveredLead,
    DiscoveryRun,
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
        "open_findings": (
            db.query(func.count(Finding.id))
            .filter(Finding.kind != "expected_surface", Finding.status == "open")
            .scalar()
            or 0
        ),
        "reports": db.query(func.count(Report.id)).scalar() or 0,
        "published_reports": db.query(func.count(Report.id)).filter(Report.status == "published").scalar() or 0,
        "discovery_new": db.query(func.count(DiscoveredLead.id)).filter(DiscoveredLead.status == "new").scalar() or 0,
        "discovery_promoted": db.query(func.count(DiscoveredLead.id)).filter(DiscoveredLead.status == "promoted").scalar() or 0,
        "discovery_runs": db.query(func.count(DiscoveryRun.id)).scalar() or 0,
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


def add_endpoint(
    db: Session,
    project: Project,
    url: str | None = None,
    *,
    kind: str = "rpc",
    address: str | None = None,
    chain_id: int | None = None,
    abi_json: str | None = None,
    source_ref: str | None = None,
    crawl_budget: int | None = None,
) -> Endpoint:
    from dapptility_scanner.providers import detect_provider

    kind = (kind or "rpc").strip().lower()
    if kind == "website":
        kind = "web"
    if kind not in {"web", "rpc", "contract"}:
        raise ValueError(f"Unknown target kind: {kind}")

    provider = None
    is_third_party = False
    provider_name = None
    if kind == "rpc" and url:
        provider = detect_provider(url)
        is_third_party = provider is not None
        provider_name = provider.provider if provider else None

    if kind in {"web", "rpc"} and not url:
        raise ValueError(f"{kind} targets require a URL")
    if kind == "contract" and not address:
        raise ValueError("contract targets require an address")
    if kind == "contract" and not url:
        raise ValueError("contract targets require an RPC URL for scanning")

    endpoint = Endpoint(
        project_id=project.id,
        kind=kind,
        url=url,
        address=address,
        chain_id=chain_id,
        abi_json=abi_json,
        source_ref=source_ref,
        crawl_budget=crawl_budget,
        is_third_party_provider=is_third_party,
        provider_name=provider_name,
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    log_action(
        db,
        "endpoint.create",
        f"endpoint_id={endpoint.id} project_id={project.id} kind={kind}",
    )
    return endpoint


def execute_scan(db: Session, endpoint: Endpoint, profile: str) -> Scan:
    from dapptility_scanner.profiles import normalize_profile_name

    module = endpoint.kind if endpoint.kind != "website" else "web"
    if module == "contract":
        if not endpoint.address or not endpoint.url:
            raise ValueError("Contract targets need address and RPC URL")
    elif not endpoint.url:
        raise ValueError("Target has no URL to scan")

    profile_name = normalize_profile_name(profile).value

    scan = Scan(
        endpoint_id=endpoint.id,
        module=module,
        profile=profile_name,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        result = run_scan_for_endpoint(
            endpoint.url,
            profile_name,
            kind=module,
            address=endpoint.address,
            chain_id=endpoint.chain_id,
            abi_json=endpoint.abi_json,
        )
        scan.status = "aborted" if result.aborted else "completed"
        scan.score = result.score
        scan.chain_id = result.chain_id if result.chain_id is not None else endpoint.chain_id
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
                    module=module,
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
                    module=module,
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
    """Standard (and legacy Outbound) prefer confirmed findings; others include open."""
    findings = [f for f in scan.findings if f.kind != "expected_surface"]
    if profile in {"Outbound", "Standard"}:
        return [f for f in findings if f.status == "confirmed"]
    return [f for f in findings if f.status in {"open", "confirmed"}]


def outreach_report_findings(scan: Scan) -> list[Finding]:
    """Preliminary outreach reports include open and confirmed findings."""
    return [
        f
        for f in scan.findings
        if f.kind != "expected_surface" and f.status in {"open", "confirmed"}
    ]


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def latest_completed_scans_by_module(db: Session, project_id: int) -> dict[str, Scan]:
    """Latest completed scan per module for a project."""
    scans = (
        db.query(Scan)
        .join(Endpoint)
        .options(joinedload(Scan.endpoint), joinedload(Scan.findings))
        .filter(Endpoint.project_id == project_id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .all()
    )
    latest: dict[str, Scan] = {}
    for scan in scans:
        module = (scan.module or scan.endpoint.kind or "rpc").lower()
        if module == "website":
            module = "web"
        if module not in latest:
            latest[module] = scan
    return latest


def list_project_findings(
    db: Session,
    project_id: int,
    *,
    module: str | None = None,
    severity: str | None = None,
    include_expected: bool = False,
) -> list[Finding]:
    """Findings across latest completed scan per module (or all completed if needed).

    Uses latest scan per module so the project view reflects current posture.
    """
    latest = latest_completed_scans_by_module(db, project_id)
    if module:
        key = module.lower()
        if key == "website":
            key = "web"
        latest = {k: v for k, v in latest.items() if k == key}

    findings: list[Finding] = []
    for mod, scan in latest.items():
        for finding in scan.findings:
            if not include_expected and finding.kind == "expected_surface":
                continue
            if severity and finding.severity.lower() != severity.lower():
                continue
            findings.append(finding)

    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            (f.module or ""),
            f.rule_id,
        )
    )
    return findings


def create_project_report(
    db: Session,
    project: Project,
    *,
    title: str | None = None,
    publish: bool = False,
) -> Report:
    """Aggregate latest web/rpc/contract scans into one project report."""
    latest = latest_completed_scans_by_module(db, project.id)
    if not latest:
        raise ValueError("No completed scans to include in a project report")

    findings = list_project_findings(db, project.id)
    findings = [f for f in findings if f.status in {"open", "confirmed"}]
    if not findings:
        raise ValueError("No open/confirmed findings across latest module scans")

    # Anchor FK on the newest of the included scans
    primary = max(
        latest.values(),
        key=lambda s: s.created_at or datetime(1970, 1, 1, tzinfo=timezone.utc),
    )
    report = create_report_draft(
        db,
        project,
        primary,
        title=title or f"Project security assessment — {project.name}",
        report_type="project",
    )
    module_summaries = [
        {
            "module": mod,
            "scan_id": scan.id,
            "profile": scan.profile,
            "score": scan.score,
            "label": scan.endpoint.label,
            "network_name": scan.network_name,
            "chain_id": scan.chain_id,
        }
        for mod, scan in sorted(latest.items())
    ]
    build_and_store_report(db, report, findings=findings, module_summaries=module_summaries)
    if publish:
        publish_report(db, report)
    return report


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
    log_action(db, "report.create", f"report_id={report.id} type={report_type}")
    return report


def build_and_store_report(
    db: Session,
    report: Report,
    *,
    findings: list[Finding] | None = None,
    module_summaries: list[dict] | None = None,
) -> Report:
    project = report.project
    scan = report.scan
    endpoint = scan.endpoint
    if findings is None:
        findings = publishable_findings(scan, scan.profile)

    html = render_report_html(
        project=project,
        endpoint=endpoint,
        scan=scan,
        findings=findings,
        report=report,
        module_summaries=module_summaries,
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
        module_summaries=module_summaries,
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


def ensure_published_outreach_report(
    db: Session,
    project: Project,
    scan: Scan,
) -> Report | None:
    """Build and publish a preliminary report for outreach, if findings exist."""
    findings = outreach_report_findings(scan)
    if not findings:
        return None

    report = (
        db.query(Report)
        .filter(Report.scan_id == scan.id, Report.status == "published")
        .order_by(Report.created_at.desc())
        .first()
    )
    if report:
        return report

    report = (
        db.query(Report)
        .filter(Report.scan_id == scan.id)
        .order_by(Report.created_at.desc())
        .first()
    )
    if report is None:
        report = create_report_draft(
            db,
            project,
            scan,
            title=f"Preliminary RPC Security Assessment — {project.name}",
            report_type="preliminary",
        )

    build_and_store_report(db, report, findings=findings)
    if report.status != "published":
        publish_report(db, report)
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
