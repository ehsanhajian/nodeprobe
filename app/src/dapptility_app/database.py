from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from dapptility_app.config import settings


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    website: Mapped[str | None] = mapped_column(String(512))
    network_type: Mapped[str | None] = mapped_column(String(64))
    project_type: Mapped[str | None] = mapped_column(String(64))
    launch_stage: Mapped[str | None] = mapped_column(String(64))
    lead_score: Mapped[int] = mapped_column(Integer, default=0)
    disclosure_contact: Mapped[str | None] = mapped_column(String(512))
    communication_notes: Mapped[str | None] = mapped_column(Text)
    do_not_contact: Mapped[bool] = mapped_column(Boolean, default=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="project")
    reports: Mapped[list["Report"]] = relationship(back_populates="project")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    # website | rpc | contract
    kind: Mapped[str] = mapped_column(String(32), default="rpc")
    url: Mapped[str | None] = mapped_column(String(1024))
    # contract targets
    address: Mapped[str | None] = mapped_column(String(128))
    chain_id: Mapped[int | None] = mapped_column(Integer)
    abi_json: Mapped[str | None] = mapped_column(Text)
    source_ref: Mapped[str | None] = mapped_column(String(512))
    # website optional crawl budget (pages)
    crawl_budget: Mapped[int | None] = mapped_column(Integer)
    is_third_party_provider: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_name: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    project: Mapped[Project] = relationship(back_populates="endpoints")
    scans: Mapped[list["Scan"]] = relationship(back_populates="endpoint")

    @property
    def label(self) -> str:
        if self.kind == "contract":
            addr = self.address or ""
            if self.chain_id is not None:
                return f"{addr} (chain {self.chain_id})"
            return addr or self.url or "contract"
        return self.url or ""

    @property
    def scanable(self) -> bool:
        if self.kind == "contract":
            return bool(self.address and self.url)
        if self.kind == "rpc" and self.is_third_party_provider:
            return False
        return bool(self.url)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), nullable=False)
    # web | rpc | contract
    module: Mapped[str] = mapped_column(String(32), default="rpc")
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    score: Mapped[int | None] = mapped_column(Integer)
    chain_id: Mapped[int | None] = mapped_column(Integer)
    network_name: Mapped[str | None] = mapped_column(String(128))
    client_version: Mapped[str | None] = mapped_column(String(256))
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    abort_reason: Mapped[str | None] = mapped_column(String(64))
    raw_result_path: Mapped[str | None] = mapped_column(String(1024))
    raw_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    endpoint: Mapped[Endpoint] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    # web | rpc | contract
    module: Mapped[str] = mapped_column(String(32), default="rpc")
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    score_impact: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="open")
    reviewer_note: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), default="preliminary")
    title: Mapped[str] = mapped_column(String(512))
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="draft")
    html_path: Mapped[str | None] = mapped_column(String(1024))
    pdf_path: Mapped[str | None] = mapped_column(String(1024))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    project: Mapped[Project] = relationship(back_populates="reports")
    scan: Mapped[Scan] = relationship(back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), default="admin")
    details: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="running")
    source: Mapped[str] = mapped_column(String(64), default="chainlist")
    chains_seen: Mapped[int] = mapped_column(Integer, default=0)
    rpc_candidates: Mapped[int] = mapped_column(Integer, default=0)
    leads_new: Mapped[int] = mapped_column(Integer, default=0)
    leads_updated: Mapped[int] = mapped_column(Integer, default=0)
    leads_promoted: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DiscoveredLead(Base):
    __tablename__ = "discovered_leads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    chain_id: Mapped[int] = mapped_column(Integer, index=True)
    chain_name: Mapped[str] = mapped_column(String(255))
    short_name: Mapped[str | None] = mapped_column(String(64))
    rpc_url: Mapped[str] = mapped_column(String(1024), unique=True, index=True)
    rpc_url_normalized: Mapped[str] = mapped_column(String(1024), index=True)
    website: Mapped[str | None] = mapped_column(String(512))
    is_testnet: Mapped[bool] = mapped_column(Boolean, default=False)
    is_third_party_provider: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_name: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(64), default="chainlist")
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    lead_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    score_breakdown_json: Mapped[str | None] = mapped_column(Text)
    discovery_run_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_runs.id"))
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"))
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    project: Mapped[Project | None] = relationship()


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _ensure_sqlite_columns() -> None:
    """Additive SQLite migrations for existing personal DBs (no Alembic yet)."""
    if not settings.database_url.startswith("sqlite"):
        return

    alterations: list[tuple[str, str, str]] = [
        ("endpoints", "kind", "VARCHAR(32) DEFAULT 'rpc'"),
        ("endpoints", "address", "VARCHAR(128)"),
        ("endpoints", "chain_id", "INTEGER"),
        ("endpoints", "abi_json", "TEXT"),
        ("endpoints", "source_ref", "VARCHAR(512)"),
        ("endpoints", "crawl_budget", "INTEGER"),
        ("scans", "module", "VARCHAR(32) DEFAULT 'rpc'"),
        ("findings", "module", "VARCHAR(32) DEFAULT 'rpc'"),
    ]
    with engine.begin() as conn:
        for table, column, col_type in alterations:
            existing = {
                row[1]
                for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            }
            if table not in {
                r[0]
                for r in conn.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }:
                continue
            if column not in existing:
                conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def raw_retention_deadline() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=settings.raw_evidence_retention_days)
