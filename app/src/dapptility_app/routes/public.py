from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload

from dapptility_app.database import Report, Scan, get_db
from dapptility_app.services import store

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

router = APIRouter()


@router.get("/r/{token}")
def view_report(request: Request, token: str, db: Session = Depends(get_db)):
    report = (
        db.query(Report)
        .options(
            joinedload(Report.project),
            joinedload(Report.scan).joinedload(Scan.endpoint),
        )
        .filter(Report.token == token)
        .first()
    )
    if not report:
        raise HTTPException(404, "Report not found")
    if report.status != "published":
        raise HTTPException(404, "Report not available")
    if report.expires_at and datetime.now(timezone.utc) > report.expires_at:
        raise HTTPException(410, "Report has expired")
    if not report.html_path or not Path(report.html_path).exists():
        store.build_and_store_report(db, report)
    html = Path(report.html_path).read_text()
    return HTMLResponse(html)


@router.get("/r/{token}/pdf")
def download_report_pdf(token: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.token == token).first()
    if not report or report.status != "published":
        raise HTTPException(404)
    if report.expires_at and datetime.now(timezone.utc) > report.expires_at:
        raise HTTPException(410)
    if not report.pdf_path:
        store.build_and_store_report(db, report)
    return FileResponse(report.pdf_path, filename="dapptility-report.pdf")
