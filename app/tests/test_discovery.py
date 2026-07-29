from __future__ import annotations

import json

import pytest

from dapptility_app.database import DiscoveredLead, Endpoint, Project, init_db
from dapptility_app import database
from dapptility_app.services.discovery.chainlist import fetch_chainlist_candidates
from dapptility_app.services.discovery.scoring import score_candidate
from dapptility_app.services.discovery.sync import promote_lead, run_discovery_sync
from dapptility_app.services.discovery.utils import RpcCandidate, normalize_rpc_url


SAMPLE_CHAINLIST = [
    {
        "name": "Example Mainnet",
        "chain": "EXM",
        "chainId": 424242,
        "shortName": "exm",
        "infoURL": "https://examplechain.org",
        "testnet": False,
        "rpc": [
            {"url": "https://rpc.examplechain.org", "tracking": "none"},
            {"url": "https://eth-mainnet.g.alchemy.com/v2/demo", "tracking": "none"},
            "wss://rpc.examplechain.org",
        ],
    },
    {
        "name": "Example Testnet",
        "chainId": 424243,
        "testnet": True,
        "rpc": [{"url": "https://testnet.examplechain.org", "tracking": "none"}],
    },
]


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DAPPILITY_DATABASE_URL", f"sqlite:///{db_path}")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    database.engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal = sessionmaker(bind=database.engine, autoflush=False, autocommit=False)
    init_db()
    session = database.SessionLocal()
    yield session
    session.close()


def test_normalize_rpc_url():
    assert normalize_rpc_url("https://RPC.Example.com/") == "https://rpc.example.com"


def test_fetch_chainlist_candidates_filters_invalid():
  class FakeResponse:
      def raise_for_status(self): ...
      def json(self): return SAMPLE_CHAINLIST
  class FakeClient:
      def get(self, url): return FakeResponse()
      def close(self): ...
  candidates = fetch_chainlist_candidates(client=FakeClient())
  urls = {c.rpc_url for c in candidates}
  assert "https://rpc.examplechain.org" in urls
  assert "https://testnet.examplechain.org" in urls
  assert all(not u.startswith("wss:") for u in urls)


def test_score_own_domain_mainnet_high():
    candidate = RpcCandidate(
        chain_id=424242,
        chain_name="Example Mainnet",
        short_name="exm",
        website="https://examplechain.org",
        rpc_url="https://rpc.examplechain.org",
        is_testnet=False,
    )
    score = score_candidate(candidate, is_new=True, is_third_party=False, provider_name=None)
    assert score.total >= 70


def test_score_provider_low():
    candidate = RpcCandidate(
        chain_id=1,
        chain_name="Ethereum",
        short_name="eth",
        website="https://ethereum.org",
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/demo",
        is_testnet=False,
    )
    score = score_candidate(candidate, is_new=True, is_third_party=True, provider_name="Alchemy")
    assert score.total < 40


def test_discovery_sync_creates_leads(db, monkeypatch):
    monkeypatch.setattr(
        "dapptility_app.services.discovery.sync.fetch_chainlist_candidates",
        lambda: fetch_chainlist_candidates(client=type("C", (), {
            "get": lambda self, url: type("R", (), {
                "raise_for_status": lambda self: None,
                "json": lambda self: SAMPLE_CHAINLIST,
            })(),
            "close": lambda self: None,
        })()),
    )
    monkeypatch.setattr(
        "dapptility_app.services.discovery.sync.probe_rpc",
        lambda url, **kw: True,
    )
    run = run_discovery_sync(db)
    assert run.status == "completed"
    assert run.leads_new >= 1
    leads = db.query(DiscoveredLead).all()
    assert any(l.rpc_url == "https://rpc.examplechain.org" for l in leads)
    assert not any(l.is_testnet for l in leads)


def test_promote_lead_creates_project(db):
    lead = DiscoveredLead(
        chain_id=424242,
        chain_name="Example Mainnet",
        rpc_url="https://rpc.examplechain.org",
        rpc_url_normalized=normalize_rpc_url("https://rpc.examplechain.org"),
        website="https://examplechain.org",
        is_testnet=False,
        lead_score=80,
        score_breakdown_json=json.dumps({"reasons": ["test"]}),
        status="new",
    )
    db.add(lead)
    db.commit()
    project = promote_lead(db, lead, auto_scan=False)
    assert project is not None
    assert db.query(Project).count() == 1
    assert db.query(Endpoint).count() == 1
    assert lead.status == "promoted"
