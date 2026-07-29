from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from dapptility_app.config import settings
from dapptility_app.database import DiscoveredLead, DiscoveryRun, Endpoint, Project
from dapptility_app.services import store
from dapptility_app.services.discovery.chainlist import fetch_chainlist_candidates
from dapptility_app.services.discovery.scoring import score_candidate
from dapptility_app.services.discovery.utils import normalize_rpc_url
from dapptility_scanner.providers import detect_provider


def run_discovery_sync(db: Session, *, actor: str = "system") -> DiscoveryRun:
    run = DiscoveryRun(status="running", source="chainlist")
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        candidates = fetch_chainlist_candidates()
        run.chains_seen = len({c.chain_id for c in candidates})
        run.rpc_candidates = len(candidates)

        existing_urls = {
            row[0]
            for row in db.query(DiscoveredLead.rpc_url_normalized).all()
        }
        existing_endpoint_urls = {
            normalize_rpc_url(url)
            for (url,) in db.query(Endpoint.url).all()
        }

        new_count = 0
        updated_count = 0
        promoted_count = 0

        for candidate in candidates:
            normalized = normalize_rpc_url(candidate.rpc_url)
            provider = detect_provider(candidate.rpc_url)
            is_third_party = provider is not None
            is_new = normalized not in existing_urls and normalized not in existing_endpoint_urls

            score = score_candidate(
                candidate,
                is_new=is_new,
                is_third_party=is_third_party,
                provider_name=provider.provider if provider else None,
            )

            lead = db.query(DiscoveredLead).filter_by(rpc_url_normalized=normalized).first()
            if lead is None:
                lead = DiscoveredLead(
                    chain_id=candidate.chain_id,
                    chain_name=candidate.chain_name,
                    short_name=candidate.short_name,
                    rpc_url=candidate.rpc_url,
                    rpc_url_normalized=normalized,
                    website=candidate.website,
                    is_testnet=candidate.is_testnet,
                    is_third_party_provider=is_third_party,
                    provider_name=provider.provider if provider else None,
                    source=candidate.source,
                    status="new",
                    lead_score=score.total,
                    score_breakdown_json=json.dumps(
                        {"breakdown": score.breakdown, "reasons": score.reasons}
                    ),
                    discovery_run_id=run.id,
                )
                db.add(lead)
                db.flush()
                new_count += 1
                existing_urls.add(normalized)
            else:
                lead.chain_name = candidate.chain_name
                lead.short_name = candidate.short_name
                lead.website = candidate.website or lead.website
                lead.is_testnet = candidate.is_testnet
                lead.is_third_party_provider = is_third_party
                lead.provider_name = provider.provider if provider else None
                lead.lead_score = score.total
                lead.score_breakdown_json = json.dumps(
                    {"breakdown": score.breakdown, "reasons": score.reasons}
                )
                lead.last_seen_at = datetime.now(timezone.utc)
                lead.discovery_run_id = run.id
                if lead.status == "dismissed":
                    pass
                updated_count += 1

            if (
                lead.status == "new"
                and not lead.is_third_party_provider
                and lead.lead_score >= settings.discovery_auto_promote_score
            ):
                if promote_lead(db, lead, actor=actor):
                    promoted_count += 1

        run.status = "completed"
        run.leads_new = new_count
        run.leads_updated = updated_count
        run.leads_promoted = promoted_count
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        store.log_action(
            db,
            "discovery.complete",
            (
                f"run_id={run.id} new={new_count} updated={updated_count} "
                f"promoted={promoted_count}"
            ),
            actor=actor,
        )
    except Exception as exc:  # noqa: BLE001
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        store.log_action(db, "discovery.failed", str(exc), actor=actor)
        raise

    db.refresh(run)
    return run


def promote_lead(db: Session, lead: DiscoveredLead, *, actor: str = "admin") -> Project | None:
    if lead.status == "promoted" and lead.project_id:
        return db.query(Project).filter_by(id=lead.project_id).first()
    if lead.is_third_party_provider:
        return None

    existing = (
        db.query(Endpoint)
        .filter(Endpoint.url == lead.rpc_url)
        .first()
    )
    if existing:
        lead.status = "duplicate"
        lead.project_id = existing.project_id
        db.commit()
        return existing.project

    project = store.create_project(
        db,
        name=lead.chain_name,
        website=lead.website,
        network_type="EVM",
        project_type="chain",
        launch_stage="testnet" if lead.is_testnet else "mainnet",
        lead_score=lead.lead_score,
        communication_notes=(
            f"Auto-discovered via {lead.source}. RPC: {lead.rpc_url}\n"
            f"Score breakdown: {lead.score_breakdown_json}"
        ),
    )
    store.add_endpoint(db, project, lead.rpc_url)
    lead.status = "promoted"
    lead.project_id = project.id
    db.commit()
    store.log_action(db, "discovery.promote", f"lead_id={lead.id} project_id={project.id}", actor=actor)
    return project


def dismiss_lead(db: Session, lead: DiscoveredLead, *, actor: str = "admin") -> DiscoveredLead:
    lead.status = "dismissed"
    db.commit()
    store.log_action(db, "discovery.dismiss", f"lead_id={lead.id}", actor=actor)
    return lead
