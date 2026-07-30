from __future__ import annotations

from nodeprobe.models import CheckKind, Finding, Severity


SEVERITY_FLOOR = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 15,
    Severity.MEDIUM: 35,
    Severity.LOW: 55,
    Severity.INFO: 70,
}


def compute_score(findings: list[Finding]) -> int:
    """Score 0–100. Expected surface and info-only items do not reduce the score."""
    score = 100
    scored = [f for f in findings if f.kind == CheckKind.FINDING]
    for finding in scored:
        impact = finding.score_impact
        if impact <= 0:
            defaults = {
                Severity.CRITICAL: 35,
                Severity.HIGH: 20,
                Severity.MEDIUM: 10,
                Severity.LOW: 5,
                Severity.INFO: 0,
            }
            impact = defaults[finding.severity]
        score -= impact
    # Floor based on worst severity present
    if scored:
        worst = min(scored, key=lambda f: list(Severity).index(f.severity))
        score = min(score, 100)
        score = max(score, 0)
        score = min(score, 100 - (0 if worst.severity == Severity.INFO else 0))
        # Ensure critical exposure cannot look "healthy"
        if any(f.severity == Severity.CRITICAL for f in scored):
            score = min(score, 40)
        elif any(f.severity == Severity.HIGH for f in scored):
            score = min(score, 65)
    return max(0, min(100, score))
