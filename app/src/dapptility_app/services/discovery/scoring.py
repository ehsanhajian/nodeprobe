from __future__ import annotations

from dataclasses import dataclass

from dapptility_app.services.discovery.utils import RpcCandidate, extract_domain


@dataclass
class ScoreResult:
    total: int
    breakdown: dict[str, int]
    reasons: list[str]


def score_candidate(
    candidate: RpcCandidate,
    *,
    is_new: bool,
    is_third_party: bool,
    provider_name: str | None,
) -> ScoreResult:
    breakdown: dict[str, int] = {}
    reasons: list[str] = []

    def add(key: str, points: int, reason: str) -> None:
        breakdown[key] = points
        if points:
            reasons.append(reason)

    if is_third_party:
        add("third_party_provider", -50, f"Hosted on {provider_name or 'third-party'} infrastructure")
    else:
        add("own_domain_rpc", 35, "RPC on a project-controlled domain (not a known provider)")

    if candidate.is_testnet:
        add("testnet", -25, "Testnet")
    else:
        add("mainnet", 25, "Mainnet")

    if candidate.website:
        add("has_website", 10, "Chain has an official website on ChainList")

    if candidate.rpc_url.startswith("https://"):
        add("https", 10, "HTTPS RPC endpoint")

    domain = extract_domain(candidate.rpc_url)
    if domain and candidate.website:
        site_domain = extract_domain(candidate.website)
        if site_domain and (domain == site_domain or domain.endswith("." + site_domain)):
            add("domain_alignment", 15, "RPC hostname aligns with project website")

    if is_new:
        add("new_discovery", 20, "Newly discovered endpoint")

    total = max(0, min(100, sum(breakdown.values())))
    return ScoreResult(total=total, breakdown=breakdown, reasons=reasons)
