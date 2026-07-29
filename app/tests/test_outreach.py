"""Tests for outreach email generation."""

from __future__ import annotations

import json

import pytest

from dapptility_app.database import DiscoveredLead, Endpoint, Finding, Project, Report, Scan, init_db
from dapptility_app import database
from dapptility_app.services.discovery.sync import batch_dismiss_leads, batch_promote_leads, dismiss_lead
from dapptility_app.services.discovery.utils import normalize_rpc_url
from dapptility_app.services.outreach import generate_outreach_email
from dapptility_app.services import store
from dapptility_app.config import settings


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DAPPILITY_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("DAPPILITY_DATA_DIR", str(data_dir))
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    database.engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal = sessionmaker(bind=database.engine, autoflush=False, autocommit=False)
    settings.data_dir = data_dir
    settings.reports_dir = data_dir / "reports"
    settings.raw_dir = data_dir / "raw"
    settings.report_base_url = "http://testserver"
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.raw_dir.mkdir(parents=True, exist_ok=True)
    init_db()
    session = database.SessionLocal()
    yield session
    session.close()


def _make_lead(db, *, status="new", chain_id=1):
    lead = DiscoveredLead(
        chain_id=chain_id,
        chain_name=f"Chain {chain_id}",
        rpc_url=f"https://rpc{chain_id}.example.com",
        rpc_url_normalized=normalize_rpc_url(f"https://rpc{chain_id}.example.com"),
        website=f"https://chain{chain_id}.example.com",
        is_testnet=False,
        lead_score=80,
        score_breakdown_json=json.dumps({"reasons": ["test"]}),
        status=status,
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return lead


def test_batch_dismiss_leads(db):
    lead1 = _make_lead(db, chain_id=1)
    lead2 = _make_lead(db, chain_id=2)
    result = batch_dismiss_leads(db, [lead1.id, lead2.id, 9999])
    assert result.dismissed == 2
    assert result.skipped == 1
    db.refresh(lead1)
    assert lead1.status == "dismissed"


def test_batch_promote_skips_third_party(db, monkeypatch):
    monkeypatch.setattr("dapptility_app.services.discovery.sync.probe_rpc", lambda *a, **k: True)
    lead = DiscoveredLead(
        chain_id=99,
        chain_name="Alchemy",
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/demo",
        rpc_url_normalized=normalize_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo"),
        is_testnet=False,
        is_third_party_provider=True,
        provider_name="Alchemy",
        lead_score=10,
        status="new",
    )
    db.add(lead)
    db.commit()
    result = batch_promote_leads(db, [lead.id], auto_scan=False)
    assert result.promoted == 0
    assert result.skipped == 1


def test_outreach_email_includes_report_link(db):
    project = store.create_project(db, name="Test Chain", website="https://test.example")
    endpoint = store.add_endpoint(db, project, "https://rpc.test.example")
    scan = Scan(
        endpoint_id=endpoint.id,
        profile="Standard",
        status="completed",
        score=42,
        chain_id=1,
        network_name="Test",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(
        Finding(
            scan_id=scan.id,
            rule_id="EVM-HTTP-001",
            title="Missing security headers",
            category="HTTP",
            severity="Medium",
            confidence="High",
            kind="finding",
            description="CORS is permissive",
            status="open",
        )
    )
    db.commit()

    report = store.create_report_draft(db, project, scan, title="Test Report")
    store.build_and_store_report(db, report, findings=store.outreach_report_findings(scan))
    store.publish_report(db, report)

    email = generate_outreach_email(db, project, scan, report=report)
    assert email is not None
    assert email.report_url == f"http://testserver/r/{report.token}"
    assert email.report_url in email.body


def test_ensure_published_outreach_report(db):
    project = store.create_project(db, name="Outreach Chain")
    endpoint = store.add_endpoint(db, project, "https://rpc.outreach.example")
    scan = Scan(endpoint_id=endpoint.id, profile="Standard", status="completed", score=50)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(
        Finding(
            scan_id=scan.id,
            rule_id="EVM-TLS-001",
            title="TLS issue",
            category="TLS",
            severity="High",
            confidence="High",
            kind="finding",
            description="Certificate problem",
            status="open",
        )
    )
    db.commit()

    report = store.ensure_published_outreach_report(db, project, scan)
    assert report is not None
    assert report.status == "published"
    assert report.html_path
