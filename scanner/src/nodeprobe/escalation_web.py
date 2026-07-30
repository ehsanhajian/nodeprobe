"""Finding-driven escalation for website scans (Standard / Deep)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse

from nodeprobe.escalation import (
    _child,
    _trim,
    max_escalations_for,
    profile_allows_escalation,
)
from nodeprobe.http_client import BudgetedHttpClient
from nodeprobe.models import CheckKind, Finding, ScanProfile, Severity

# Sensitive path probes — read-only, capped. Only report interesting 200s.
_SENSITIVE_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/config.json",
    "/admin/",
    "/api/",
)


def _mark_parent(parent: Finding, children: list[Finding]) -> None:
    if not children:
        return
    parent.evidence = {
        **(parent.evidence or {}),
        "escalation_ran": True,
        "escalation_children": [c.rule_id for c in children],
    }


def _escalate_missing_hsts(
    client: BudgetedHttpClient, context: dict[str, Any], parent: Finding
) -> list[Finding]:
    """If HSTS is missing, check whether cleartext HTTP is still reachable."""
    primary = context.get("primary")
    base = urlparse((primary.final_url if primary else None) or client.target.original_url)
    if base.scheme != "https" or not base.hostname:
        return [
            _child(
                parent=parent,
                step="NEXT",
                title="Next: primary URL is not HTTPS — HSTS less relevant",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description="Site is not served over HTTPS on the scanned URL.",
                evidence={"scheme": base.scheme},
                score_impact=4,
            )
        ]

    http_url = urlunparse(
        ("http", base.netloc, base.path or "/", "", "", "")
    )
    try:
        exchange = client.get(http_url, follow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return [
            _child(
                parent=parent,
                step="CONFIRM",
                title="Next: cleartext HTTP probe failed",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description=f"Could not confirm HTTP downgrade path: {exc}",
                evidence={"http_url": http_url, "error": str(exc)},
                score_impact=0,
            )
        ]

    final = urlparse(exchange.final_url)
    redirected_https = final.scheme == "https"
    out = [
        _child(
            parent=parent,
            step="CONFIRM",
            title=(
                "Next: HTTP redirects to HTTPS"
                if redirected_https
                else "Next: cleartext HTTP still serves content"
            ),
            severity=Severity.LOW if redirected_https else Severity.HIGH,
            kind=CheckKind.FINDING if not redirected_https else CheckKind.INFO,
            description=(
                f"Probed {http_url} → {exchange.final_url} (status {exchange.status_code}). "
                + (
                    "Redirect to HTTPS exists, but HSTS is still missing (first visit / MITM risk)."
                    if redirected_https
                    else "Cleartext HTTP remains usable — downgrade / sniffing risk is real."
                )
            ),
            evidence={
                "http_url": http_url,
                "final_url": exchange.final_url,
                "status": exchange.status_code,
                "redirect_chain": exchange.redirect_chain[:5],
                "redirected_https": redirected_https,
            },
            score_impact=0 if redirected_https else 14,
            impact="Missing HSTS enables SSL stripping when HTTP remains reachable.",
            remediation="Enable HSTS (includeSubDomains; preload when ready) and redirect HTTP→HTTPS.",
        )
    ]
    return out


def _escalate_missing_csp(
    client: BudgetedHttpClient, context: dict[str, Any], parent: Finding
) -> list[Finding]:
    """If CSP is missing, check framing headers and inline script surface."""
    primary = context.get("primary") or client.get()
    body = primary.body_text or ""
    headers = primary.headers
    xfo = headers.get("x-frame-options")
    frame_ancestors = "frame-ancestors" in (headers.get("content-security-policy") or "").lower()
    script_tags = body.lower().count("<script")
    has_inline = "<script>" in body.lower() or "onclick=" in body.lower()

    out: list[Finding] = []
    if not xfo and not frame_ancestors:
        out.append(
            _child(
                parent=parent,
                step="NEXT",
                title="Next: no CSP and no frame controls",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description=(
                    "Missing CSP and neither X-Frame-Options nor CSP frame-ancestors — "
                    "clickjacking defenses are absent."
                ),
                evidence={"x_frame_options": xfo, "frame_ancestors": frame_ancestors},
                score_impact=8,
                impact="Pages can be framed by third-party sites.",
                remediation="Set CSP frame-ancestors or X-Frame-Options: DENY/SAMEORIGIN.",
            )
        )
    else:
        out.append(
            _child(
                parent=parent,
                step="CONFIRM",
                title="Next: framing partially covered without CSP",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description=(
                    "CSP is missing but framing is constrained via "
                    + ("CSP frame-ancestors" if frame_ancestors else f"X-Frame-Options: {xfo}")
                    + ". XSS / resource controls still need CSP."
                ),
                evidence={"x_frame_options": xfo, "frame_ancestors": frame_ancestors},
                score_impact=0,
            )
        )

    if has_inline or script_tags >= 2:
        out.append(
            _child(
                parent=parent,
                step="DEEPEN",
                title="Next: page uses inline script surface without CSP",
                severity=Severity.MEDIUM,
                kind=CheckKind.FINDING,
                description=(
                    f"HTML contains ~{script_tags} script tag(s)"
                    + (" and inline handlers/snippets" if has_inline else "")
                    + ". Without CSP, XSS impact is harder to contain."
                ),
                evidence={
                    "script_tags": script_tags,
                    "inline_hints": has_inline,
                    "body_bytes": len(body),
                },
                score_impact=6,
                remediation="Add a strict CSP (default-src/script-src) and prefer nonces/hashes.",
            )
        )
    return out


def _escalate_server_disclosure(
    client: BudgetedHttpClient, context: dict[str, Any], parent: Finding
) -> list[Finding]:
    """Technology banner → probe a few common disclosure paths (read-only)."""
    if client.limits.name == ScanProfile.QUICK:
        return []
    value = str((parent.evidence or {}).get("value") or "").lower()
    paths = list(_SENSITIVE_PATHS)
    if "s3" in value or "amazon" in value:
        paths = ["/", "/.env", "/config.json"] + paths
    # Cap probes
    limit = 4 if client.limits.name == ScanProfile.DEEP else 3
    interesting: list[dict[str, Any]] = []
    for path in paths[:limit]:
        try:
            exchange = client.get(path, follow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        if exchange.status_code != 200:
            continue
        body = exchange.body_text or ""
        snippet = body[:200]
        looks_sensitive = any(
            token in body.lower()
            for token in ("apikey", "api_key", "secret", "password", "aws_", "private key", "ref: refs/")
        ) or (path.endswith(".env") and "=" in body) or (path == "/.git/HEAD" and body.startswith("ref:"))
        if looks_sensitive or (path in {"/.env", "/.git/HEAD"} and len(body) > 0):
            interesting.append(
                {
                    "path": path,
                    "status": exchange.status_code,
                    "bytes": len(body),
                    "snippet": _trim(snippet, 100),
                }
            )

    if not interesting:
        return [
            _child(
                parent=parent,
                step="NEXT",
                title="Next: common sensitive paths not openly readable",
                severity=Severity.INFO,
                kind=CheckKind.INFO,
                description=(
                    f"Server banner `{parent.evidence.get('value')}` noted; "
                    "spot-checks of common sensitive paths did not return obvious secrets."
                ),
                evidence={"probed": paths[:limit], "hits": []},
                score_impact=0,
            )
        ]
    return [
        _child(
            parent=parent,
            step="IMPACT",
            title=f"Next: {len(interesting)} sensitive path(s) returned content",
            severity=Severity.HIGH,
            kind=CheckKind.FINDING,
            description=(
                "After server/technology disclosure, follow-up GETs returned readable content "
                "on sensitive-looking paths."
            ),
            evidence={"hits": interesting, "server": parent.evidence.get("value")},
            score_impact=18,
            impact="Public secrets or VCS metadata enable further compromise.",
            remediation="Block sensitive paths at the edge; rotate any exposed credentials.",
        )
    ]


def _escalate_security_txt_gap(
    client: BudgetedHttpClient, context: dict[str, Any], parent: Finding, findings: list[Finding]
) -> list[Finding]:
    """Missing security.txt + other Medium+ web issues → combined disclosure gap."""
    medium_plus = [
        f
        for f in findings
        if f.parent_rule_id is None
        and f.kind == CheckKind.FINDING
        and f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
        and f.rule_id != parent.rule_id
    ]
    if not medium_plus:
        return []
    return [
        _child(
            parent=parent,
            step="NEXT",
            title="Next: no security.txt while other Medium+ issues exist",
            severity=Severity.LOW,
            kind=CheckKind.FINDING,
            description=(
                f"security.txt is missing and the scan also found {len(medium_plus)} "
                "Medium+ finding(s). Researchers lack a clear disclosure channel."
            ),
            evidence={
                "related_findings": [f.rule_id for f in medium_plus[:8]],
                "related_titles": [f.title for f in medium_plus[:5]],
            },
            score_impact=3,
            remediation="Publish /.well-known/security.txt with Contact.",
        )
    ]


def run_web_escalations(
    client: BudgetedHttpClient,
    context: dict[str, Any],
    findings: list[Finding],
) -> list[Finding]:
    profile = client.limits.name
    if not profile_allows_escalation(profile):
        return []

    budget = max_escalations_for(profile)
    produced: list[Finding] = []

    def _take(parent: Finding, kids: list[Finding]) -> None:
        nonlocal produced
        if not kids:
            return
        room = budget - len(produced)
        if room <= 0:
            return
        chunk = kids[:room]
        _mark_parent(parent, chunk)
        produced.extend(chunk)

    # Prefer specific header findings by evidence/title
    for parent in findings:
        if len(produced) >= budget:
            break
        if parent.parent_rule_id or parent.kind != CheckKind.FINDING:
            continue
        header = str((parent.evidence or {}).get("header") or "").lower()
        title = parent.title.lower()

        if parent.rule_id == "WEB-HDR-001" and (
            header == "strict-transport-security" or "hsts" in title
        ):
            if parent.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}:
                try:
                    _take(parent, _escalate_missing_hsts(client, context, parent))
                except Exception:  # noqa: BLE001
                    pass
        elif parent.rule_id == "WEB-HDR-001" and (
            header == "content-security-policy" or "content-security-policy" in title
        ):
            if parent.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}:
                try:
                    _take(parent, _escalate_missing_csp(client, context, parent))
                except Exception:  # noqa: BLE001
                    pass
        elif parent.rule_id == "WEB-HDR-002" and header == "server":
            try:
                _take(parent, _escalate_server_disclosure(client, context, parent))
            except Exception:  # noqa: BLE001
                pass
        elif parent.rule_id == "WEB-WKN-001":
            try:
                _take(parent, _escalate_security_txt_gap(client, context, parent, findings))
            except Exception:  # noqa: BLE001
                pass

    return produced
