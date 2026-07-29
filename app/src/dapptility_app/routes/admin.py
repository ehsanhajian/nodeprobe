import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload

from dapptility_app.auth import verify_admin
from dapptility_app.database import DiscoveredLead, DiscoveryRun, Endpoint, Finding, Project, Report, Scan, get_db
from dapptility_app.services.discovery.sync import (
    batch_dismiss_leads,
    batch_promote_leads,
    dismiss_lead,
    promote_lead,
    run_discovery_sync,
)
from dapptility_app.services.outreach import generate_outreach_email
from dapptility_app.services import store

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _score_reasons(lead: DiscoveredLead) -> list[str]:
    if not lead.score_breakdown_json:
        return []
    try:
        data = json.loads(lead.score_breakdown_json)
    except json.JSONDecodeError:
        return []
    return list(data.get("reasons") or [])


templates.env.filters["score_reasons"] = _score_reasons

DISCOVERY_PAGE_SIZE = 25


def _score_tier(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


templates.env.filters["score_tier"] = _score_tier

router = APIRouter(prefix="/admin", dependencies=[Depends(verify_admin)])


@router.get("")
def dashboard(request: Request, db: Session = Depends(get_db)):
    stats = store.dashboard_stats(db)
    recent_scans = (
        db.query(Scan)
        .options(joinedload(Scan.endpoint).joinedload(Endpoint.project))
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {"stats": stats, "recent_scans": recent_scans},
    )


@router.get("/projects")
def projects_list(request: Request, db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.archived.is_(False)).order_by(Project.created_at.desc()).all()
    return templates.TemplateResponse(
        request,
        "admin/projects.html",
        {"projects": projects},
    )


@router.get("/projects/new")
def project_new(request: Request):
    return templates.TemplateResponse(request, "admin/project_form.html", {"project": None})


@router.post("/projects/new")
def project_create(
    request: Request,
    name: str = Form(...),
    website: str = Form(""),
    network_type: str = Form(""),
    project_type: str = Form(""),
    launch_stage: str = Form(""),
    lead_score: int = Form(0),
    disclosure_contact: str = Form(""),
    communication_notes: str = Form(""),
    db: Session = Depends(get_db),
):
    project = store.create_project(
        db,
        name=name,
        website=website or None,
        network_type=network_type or None,
        project_type=project_type or None,
        launch_stage=launch_stage or None,
        lead_score=lead_score,
        disclosure_contact=disclosure_contact or None,
        communication_notes=communication_notes or None,
    )
    return RedirectResponse(f"/admin/projects/{project.id}", status_code=303)


@router.get("/projects/{project_id}")
def project_detail(request: Request, project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404)
    endpoints = db.query(Endpoint).filter(Endpoint.project_id == project_id).all()
    reports = db.query(Report).filter(Report.project_id == project_id).order_by(Report.created_at.desc()).all()
    scans = (
        db.query(Scan)
        .join(Endpoint)
        .filter(Endpoint.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return templates.TemplateResponse(
        request,
        "admin/project_detail.html",
        {"project": project, "endpoints": endpoints, "reports": reports, "scans": scans},
    )


@router.post("/projects/{project_id}/endpoints")
def endpoint_add(
    project_id: int,
    kind: str = Form("rpc"),
    url: str = Form(""),
    address: str = Form(""),
    chain_id: str = Form(""),
    source_ref: str = Form(""),
    crawl_budget: str = Form(""),
    db: Session = Depends(get_db),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404)
    parsed_chain: int | None = None
    if chain_id.strip():
        try:
            parsed_chain = int(chain_id.strip())
        except ValueError as exc:
            raise HTTPException(400, "chain_id must be an integer") from exc
    parsed_budget: int | None = None
    if crawl_budget.strip():
        try:
            parsed_budget = int(crawl_budget.strip())
        except ValueError as exc:
            raise HTTPException(400, "crawl_budget must be an integer") from exc
    try:
        store.add_endpoint(
            db,
            project,
            url=url.strip() or None,
            kind=kind,
            address=address.strip() or None,
            chain_id=parsed_chain,
            source_ref=source_ref.strip() or None,
            crawl_budget=parsed_budget,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/admin/projects/{project_id}", status_code=303)


@router.post("/projects/{project_id}/archive")
def project_archive(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404)
    store.update_project(db, project, archived=True)
    return RedirectResponse("/admin/projects", status_code=303)


@router.post("/endpoints/{endpoint_id}/scan")
def scan_start(
    endpoint_id: int,
    profile: str = Form("Outbound"),
    db: Session = Depends(get_db),
):
    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(404)
    if endpoint.kind == "rpc" and endpoint.is_third_party_provider:
        raise HTTPException(400, "Cannot scan third-party provider endpoint")
    if not endpoint.scanable:
        raise HTTPException(400, "Target cannot be scanned (contract needs address + RPC URL)")
    try:
        scan = store.execute_scan(db, endpoint, profile)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/admin/scans/{scan.id}", status_code=303)


@router.get("/scans/{scan_id}")
def scan_detail(request: Request, scan_id: int, db: Session = Depends(get_db)):
    scan = (
        db.query(Scan)
        .options(
            joinedload(Scan.endpoint).joinedload(Endpoint.project),
            joinedload(Scan.findings),
        )
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(404)
    raw_available = store.load_raw_scan(scan) is not None
    outreach_report = (
        db.query(Report)
        .filter(Report.scan_id == scan.id, Report.status == "published")
        .order_by(Report.created_at.desc())
        .first()
    )
    email_draft = generate_outreach_email(
        db,
        scan.endpoint.project,
        scan,
        report=outreach_report,
    )
    return templates.TemplateResponse(
        request,
        "admin/scan_detail.html",
        {
            "scan": scan,
            "raw_available": raw_available,
            "email_draft": email_draft,
            "outreach_report": outreach_report,
            "report_published": request.query_params.get("report_published") == "1",
        },
    )


@router.post("/scans/{scan_id}/outreach-report")
def scan_publish_outreach_report(scan_id: int, db: Session = Depends(get_db)):
    scan = (
        db.query(Scan)
        .options(
            joinedload(Scan.endpoint).joinedload(Endpoint.project),
            joinedload(Scan.findings),
        )
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(404)
    report = store.ensure_published_outreach_report(db, scan.endpoint.project, scan)
    if report is None:
        raise HTTPException(400, "No actionable findings to publish in a report")
    return RedirectResponse(f"/admin/scans/{scan_id}?report_published=1", status_code=303)


@router.get("/scans/{scan_id}/raw")
def scan_raw(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404)
    raw = store.load_raw_scan(scan)
    if raw is None:
        raise HTTPException(404, "Raw evidence unavailable or expired")
    return raw


@router.post("/findings/{finding_id}/status")
def finding_status(
    finding_id: int,
    status: str = Form(...),
    reviewer_note: str = Form(""),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404)
    store.update_finding_status(db, finding, status, reviewer_note or None)
    return RedirectResponse(f"/admin/scans/{finding.scan_id}", status_code=303)


@router.post("/scans/{scan_id}/report")
def report_create(
    scan_id: int,
    title: str = Form(...),
    report_type: str = Form("preliminary"),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.endpoint).joinedload(Endpoint.project))
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(404)
    report = store.create_report_draft(
        db,
        scan.endpoint.project,
        scan,
        title=title,
        report_type=report_type,
    )
    store.build_and_store_report(db, report)
    return RedirectResponse(f"/admin/reports/{report.id}", status_code=303)


@router.get("/reports/{report_id}")
def report_detail(request: Request, report_id: int, db: Session = Depends(get_db)):
    report = (
        db.query(Report)
        .options(
            joinedload(Report.project),
            joinedload(Report.scan).joinedload(Scan.endpoint),
        )
        .filter(Report.id == report_id)
        .first()
    )
    if not report:
        raise HTTPException(404)
    return templates.TemplateResponse(
        request,
        "admin/report_detail.html",
        {"report": report},
    )


@router.post("/reports/{report_id}/publish")
def report_publish(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404)
    store.publish_report(db, report)
    return RedirectResponse(f"/admin/reports/{report.id}", status_code=303)


@router.post("/reports/{report_id}/revoke")
def report_revoke(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404)
    store.revoke_report(db, report)
    return RedirectResponse(f"/admin/reports/{report.id}", status_code=303)


@router.get("/reports/{report_id}/preview")
def report_preview(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not report.html_path:
        raise HTTPException(404)
    return HTMLResponse(Path(report.html_path).read_text())


@router.get("/reports/{report_id}/pdf")
def report_pdf_download(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not report.pdf_path:
        raise HTTPException(404)
    return FileResponse(report.pdf_path, filename=f"report-{report.id}.pdf")


@router.get("/discovery")
def discovery_list(
    request: Request,
    db: Session = Depends(get_db),
    status: str = "new",
    page: int = 1,
    promoted: int | None = None,
    dismissed: int | None = None,
    skipped: int | None = None,
):
    page = max(1, page)
    base_query = db.query(DiscoveredLead).filter(
        DiscoveredLead.is_testnet == False,  # noqa: E712
    ).order_by(
        DiscoveredLead.lead_score.desc(),
        DiscoveredLead.id.desc(),
    )
    if status != "all":
        base_query = base_query.filter(DiscoveredLead.status == status)

    total = base_query.count()
    total_pages = max(1, (total + DISCOVERY_PAGE_SIZE - 1) // DISCOVERY_PAGE_SIZE)
    if page > total_pages:
        page = total_pages
    leads = (
        base_query.offset((page - 1) * DISCOVERY_PAGE_SIZE)
        .limit(DISCOVERY_PAGE_SIZE)
        .all()
    )

    _mainnet_filter = DiscoveredLead.is_testnet == False  # noqa: E712
    status_counts = {
        "new": db.query(DiscoveredLead).filter(_mainnet_filter, DiscoveredLead.status == "new").count(),
        "promoted": db.query(DiscoveredLead).filter(_mainnet_filter, DiscoveredLead.status == "promoted").count(),
        "dismissed": db.query(DiscoveredLead).filter(_mainnet_filter, DiscoveredLead.status == "dismissed").count(),
        "all": db.query(DiscoveredLead).filter(_mainnet_filter).count(),
    }
    runs = db.query(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(5).all()
    last_run = runs[0] if runs else None

    return templates.TemplateResponse(
        request,
        "admin/discovery.html",
        {
            "leads": leads,
            "runs": runs,
            "last_run": last_run,
            "status": status,
            "page": page,
            "total": total,
            "total_pages": total_pages,
            "page_size": DISCOVERY_PAGE_SIZE,
            "status_counts": status_counts,
            "flash": {
                "promoted": promoted,
                "dismissed": dismissed,
                "skipped": skipped,
            },
        },
    )


@router.post("/discovery/batch")
def discovery_batch(
    action: str = Form(...),
    lead_ids: list[int] = Form(default=[]),
    status: str = Form("new"),
    page: int = Form(1),
    auto_scan: str = Form("false"),
    db: Session = Depends(get_db),
):
    if not lead_ids:
        return RedirectResponse(f"/admin/discovery?status={status}&page={page}&skipped=0", status_code=303)

    if action == "dismiss":
        result = batch_dismiss_leads(db, lead_ids, actor="admin")
    elif action == "promote":
        result = batch_promote_leads(
            db,
            lead_ids,
            actor="admin",
            auto_scan=auto_scan.lower() in {"1", "true", "yes", "on"},
        )
    else:
        raise HTTPException(400, "Unknown batch action")

    return RedirectResponse(
        (
            f"/admin/discovery?status={status}&page={page}"
            f"&promoted={result.promoted}&dismissed={result.dismissed}&skipped={result.skipped}"
        ),
        status_code=303,
    )


@router.post("/discovery/run")
def discovery_run_now(db: Session = Depends(get_db)):
    run_discovery_sync(db, actor="admin")
    return RedirectResponse("/admin/discovery", status_code=303)


@router.post("/discovery/{lead_id}/promote")
def discovery_promote(lead_id: int, db: Session = Depends(get_db)):
    lead = db.query(DiscoveredLead).filter(DiscoveredLead.id == lead_id).first()
    if not lead:
        raise HTTPException(404)
    project = promote_lead(db, lead, actor="admin")
    if project is None:
        raise HTTPException(400, "Cannot promote third-party provider endpoint")
    return RedirectResponse(f"/admin/projects/{project.id}", status_code=303)


@router.post("/discovery/{lead_id}/dismiss")
def discovery_dismiss(
    lead_id: int,
    db: Session = Depends(get_db),
    status: str = Form("new"),
    page: int = Form(1),
):
    lead = db.query(DiscoveredLead).filter(DiscoveredLead.id == lead_id).first()
    if not lead:
        raise HTTPException(404)
    dismiss_lead(db, lead, actor="admin")
    return RedirectResponse(f"/admin/discovery?status={status}&page={page}", status_code=303)
