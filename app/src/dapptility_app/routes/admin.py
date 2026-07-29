import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload

from dapptility_app.auth import verify_admin
from dapptility_app.database import DiscoveredLead, DiscoveryRun, Endpoint, Finding, Project, Report, Scan, get_db
from dapptility_app.services.discovery.sync import dismiss_lead, promote_lead, run_discovery_sync
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
    return templates.TemplateResponse(
        request,
        "admin/project_detail.html",
        {"project": project, "endpoints": endpoints, "reports": reports},
    )


@router.post("/projects/{project_id}/endpoints")
def endpoint_add(
    project_id: int,
    url: str = Form(...),
    db: Session = Depends(get_db),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404)
    store.add_endpoint(db, project, url)
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
    if endpoint.is_third_party_provider:
        raise HTTPException(400, "Cannot scan third-party provider endpoint")
    scan = store.execute_scan(db, endpoint, profile)
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
    return templates.TemplateResponse(
        request,
        "admin/scan_detail.html",
        {"scan": scan, "raw_available": raw_available},
    )


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
def discovery_list(request: Request, db: Session = Depends(get_db), status: str = "new"):
    query = db.query(DiscoveredLead).order_by(DiscoveredLead.lead_score.desc())
    if status != "all":
        query = query.filter(DiscoveredLead.status == status)
    leads = query.limit(200).all()
    runs = db.query(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(10).all()
    return templates.TemplateResponse(
        request,
        "admin/discovery.html",
        {"leads": leads, "runs": runs, "status": status},
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
def discovery_dismiss(lead_id: int, db: Session = Depends(get_db)):
    lead = db.query(DiscoveredLead).filter(DiscoveredLead.id == lead_id).first()
    if not lead:
        raise HTTPException(404)
    dismiss_lead(db, lead, actor="admin")
    return RedirectResponse("/admin/discovery", status_code=303)
