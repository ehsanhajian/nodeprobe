from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from dapptility_app.config import settings
from dapptility_app.database import Endpoint, Project, Report, Scan, init_db
from dapptility_app import database
from dapptility_app.main import create_app
from dapptility_app.models_compat import make_scan_result
from dapptility_app.services import store


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DAPPILITY_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("DAPPILITY_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DAPPILITY_ADMIN_PASSWORD", "testpass")
    monkeypatch.setenv("DAPPILITY_REPORT_BASE_URL", "http://testserver")

    # Reload settings paths
    settings.database_url = f"sqlite:///{db_path}"
    settings.data_dir = data_dir
    settings.reports_dir = data_dir / "reports"
    settings.raw_dir = data_dir / "raw"
    settings.admin_password = "testpass"
    settings.report_base_url = "http://testserver"
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.raw_dir.mkdir(parents=True, exist_ok=True)

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import dapptility_app.database as dbmod

    dbmod.engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
    )
    dbmod.SessionLocal = sessionmaker(bind=dbmod.engine, autoflush=False, autocommit=False)
    init_db()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def auth():
    return ("admin", "testpass")


@pytest.fixture()
def mock_scan(monkeypatch):
    def _mock(url: str, profile: str):
        return make_scan_result(url, profile)

    monkeypatch.setattr("dapptility_app.services.store.run_scan_for_endpoint", _mock)


def test_admin_requires_auth(client):
    assert client.get("/admin").status_code == 401


def test_project_scan_report_flow(client, auth, mock_scan):
    r = client.post(
        "/admin/projects/new",
        data={"name": "Test Chain", "website": "https://test.example"},
        auth=auth,
        follow_redirects=False,
    )
    assert r.status_code == 303
    project_id = int(r.headers["location"].split("/")[-1])

    r = client.post(
        f"/admin/projects/{project_id}/endpoints",
        data={"url": "https://rpc.test.example"},
        auth=auth,
        follow_redirects=False,
    )
    assert r.status_code == 303

    db = database.SessionLocal()
    endpoint = db.query(Endpoint).filter_by(project_id=project_id).first()
    db.close()
    assert endpoint is not None

    r = client.post(
        f"/admin/endpoints/{endpoint.id}/scan",
        data={"profile": "Outbound"},
        auth=auth,
        follow_redirects=False,
    )
    assert r.status_code == 303
    scan_id = int(r.headers["location"].split("/")[-1])

    db = database.SessionLocal()
    scan = db.query(Scan).filter_by(id=scan_id).first()
    finding = next(f for f in scan.findings if f.kind == "finding")
    store.update_finding_status(db, finding, "confirmed")
    db.close()

    r = client.post(
        f"/admin/scans/{scan_id}/report",
        data={"title": "Test Report", "report_type": "preliminary"},
        auth=auth,
        follow_redirects=False,
    )
    assert r.status_code == 303
    report_id = int(r.headers["location"].split("/")[-1])

    db = database.SessionLocal()
    report = db.query(Report).filter_by(id=report_id).first()
    token = report.token
    db.close()

    r = client.post(f"/admin/reports/{report_id}/publish", auth=auth, follow_redirects=False)
    assert r.status_code == 303

    public = client.get(f"/r/{token}")
    assert public.status_code == 200
    assert "What we did" in public.text
    assert "Test Report" in public.text

    pdf = client.get(f"/r/{token}/pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"


def test_raw_evidence_admin_only(client, auth, mock_scan):
    client.post(
        "/admin/projects/new",
        data={"name": "Raw Test"},
        auth=auth,
        follow_redirects=False,
    )
    db = database.SessionLocal()
    project = db.query(Project).first()
    endpoint = store.add_endpoint(db, project, "https://rpc.raw.example")
    scan = store.execute_scan(db, endpoint, "Free")
    scan_id = scan.id
    db.close()

    assert client.get(f"/admin/scans/{scan_id}/raw").status_code == 401
    raw = client.get(f"/admin/scans/{scan_id}/raw", auth=auth)
    assert raw.status_code == 200
    data = raw.json()
    assert data["profile"] == "Free"


def test_third_party_endpoint_blocked(client, auth):
    client.post(
        "/admin/projects/new",
        data={"name": "Provider Test"},
        auth=auth,
        follow_redirects=False,
    )
    db = database.SessionLocal()
    project = db.query(Project).first()
    endpoint = store.add_endpoint(
        db, project, "https://eth-mainnet.g.alchemy.com/v2/demo"
    )
    endpoint_id = endpoint.id
    db.close()
    assert endpoint.is_third_party_provider is True

    r = client.post(
        f"/admin/endpoints/{endpoint_id}/scan",
        data={"profile": "Outbound"},
        auth=auth,
    )
    assert r.status_code == 400
