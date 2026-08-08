"""Scan report formatting — human (terminal) and HTML."""

from __future__ import annotations

import html
import os
import sys
from datetime import datetime, timezone

from nodeprobe.models import Finding, ScanResult, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_HEX = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#a16207",
    Severity.INFO: "#0891b2",
}


class _Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN = "\033[96m"


_SEVERITY_STYLE = {
    Severity.CRITICAL: _Style.BOLD + _Style.BRIGHT_RED,
    Severity.HIGH: _Style.BOLD + _Style.RED,
    Severity.MEDIUM: _Style.BOLD + _Style.BRIGHT_YELLOW,
    Severity.LOW: _Style.YELLOW,
    Severity.INFO: _Style.CYAN,
}


def use_color(*, stream=None, force: bool | None = None) -> bool:
    """Decide whether ANSI colors should be applied."""
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    out = stream if stream is not None else sys.stdout
    return hasattr(out, "isatty") and out.isatty()


def _paint(text: str, *codes: str, enabled: bool) -> str:
    if not enabled or not codes:
        return text
    return f"{''.join(codes)}{text}{_Style.RESET}"


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.rule_id, f.title),
    )


def _ordered_findings(findings: list[Finding]) -> list[Finding]:
    """Parents by severity, each followed immediately by its escalation children."""
    parents = [f for f in findings if not f.parent_rule_id]
    children_map: dict[str, list[Finding]] = {}
    orphans: list[Finding] = []
    for f in findings:
        if not f.parent_rule_id:
            continue
        if any(p.rule_id == f.parent_rule_id for p in parents):
            children_map.setdefault(f.parent_rule_id, []).append(f)
        else:
            orphans.append(f)
    parents = _sorted_findings(parents)
    ordered: list[Finding] = []
    for parent in parents:
        ordered.append(parent)
        kids = children_map.get(parent.rule_id, [])
        kids.sort(key=lambda k: k.rule_id)
        ordered.extend(kids)
    ordered.extend(_sorted_findings(orphans))
    return ordered


def _parent_groups(findings: list[Finding]) -> list[tuple[Finding, list[Finding]]]:
    """Return (parent, children) pairs in severity order, plus orphan parents."""
    ordered = _ordered_findings(findings)
    groups: list[tuple[Finding, list[Finding]]] = []
    i = 0
    while i < len(ordered):
        f = ordered[i]
        if f.parent_rule_id:
            groups.append((f, []))
            i += 1
            continue
        kids: list[Finding] = []
        j = i + 1
        while j < len(ordered) and ordered[j].parent_rule_id == f.rule_id:
            kids.append(ordered[j])
            j += 1
        groups.append((f, kids))
        i = j
    return groups


def _hr_duration(ms: int) -> str:
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms / 1000:.1f}s"


def _score_style(score: int) -> str:
    if score >= 80:
        return _Style.BOLD + _Style.GREEN
    if score >= 60:
        return _Style.BOLD + _Style.YELLOW
    if score >= 40:
        return _Style.BOLD + _Style.BRIGHT_YELLOW
    return _Style.BOLD + _Style.BRIGHT_RED


def _score_hex(score: int) -> str:
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#ca8a04"
    if score >= 40:
        return "#d97706"
    return "#dc2626"


def _evidence_parts(finding: Finding, *, limit: int = 80) -> list[str]:
    parts: list[str] = []
    for key_name, value in (finding.evidence or {}).items():
        if key_name in {"escalation_ran", "escalation_children"}:
            continue
        text = str(value)
        if len(text) > limit:
            text = text[: limit - 3] + "..."
        parts.append(f"{key_name}={text}")
    return parts


def _child_title(finding: Finding) -> str:
    title = finding.title
    if finding.parent_rule_id and not title.lower().startswith("next"):
        return f"Next · {title}"
    return title


def format_human_report(
    result: ScanResult,
    *,
    color: bool | None = None,
    verbose: bool = False,
) -> str:
    """Compact terminal report. Pass verbose=True for evidence on every finding."""
    enabled = use_color(force=color)
    summary = result.to_dict()["summary"]
    lines: list[str] = []

    def row(key: str, value: str) -> str:
        return f"{_paint(f'{key:<10}', _Style.DIM, enabled=enabled)} {value}"

    def section(title: str, *styles: str) -> None:
        lines.append("")
        lines.append(_paint(title, *styles, enabled=enabled))
        lines.append(_paint("─" * 68, _Style.DIM, enabled=enabled))

    rule = _paint("═" * 68, _Style.DIM, enabled=enabled)
    lines.append(
        _paint("Nodeprobe scan report", _Style.BOLD, _Style.BRIGHT_CYAN, enabled=enabled)
    )
    lines.append(rule)
    lines.append(row("Target", result.endpoint))
    lines.append(row("Profile", result.profile.value))
    lines.append(
        row("Score", _paint(f"{result.score}/100", _score_style(result.score), enabled=enabled))
    )
    lines.append(
        row(
            "Duration",
            f"{_hr_duration(result.duration_ms)} · {result.requests_made} request(s)",
        )
    )
    if result.network_name or result.chain_id is not None:
        chain = result.network_name or "unknown"
        chain_label = (
            f"{chain} ({result.chain_id})"
            if result.chain_id is not None
            else chain
        )
        lines.append(row("Chain", chain_label))
    if result.client_version:
        lines.append(row("Client", result.client_version))
    if result.provider:
        lines.append(row("Provider", result.provider))
    if result.aborted:
        lines.append(
            row(
                "Status",
                _paint(
                    f"ABORTED ({result.abort_reason})",
                    _Style.BOLD,
                    _Style.BRIGHT_RED,
                    enabled=enabled,
                ),
            )
        )
    else:
        lines.append(row("Status", _paint("completed", _Style.GREEN, enabled=enabled)))

    section("Summary", _Style.BOLD)
    bits = []
    for name, key, sev in (
        ("Critical", "critical", Severity.CRITICAL),
        ("High", "high", Severity.HIGH),
        ("Medium", "medium", Severity.MEDIUM),
        ("Low", "low", Severity.LOW),
        ("Info", "info", Severity.INFO),
    ):
        n = summary[key]
        style = _SEVERITY_STYLE[sev] if n else _Style.DIM
        bits.append(f"{name} {_paint(str(n), style, enabled=enabled)}")
    bits.append(
        f"Expected {_paint(str(summary['expected_surface']), _Style.DIM, enabled=enabled)}"
    )
    lines.append("  " + "  ".join(bits))

    if result.errors:
        section("Errors", _Style.BOLD, _Style.BRIGHT_RED)
        for err in result.errors:
            code = _paint(f"[{err.code}]", _Style.RED, enabled=enabled)
            lines.append(f"  {code} {err.message}")

    groups = _parent_groups(result.findings)
    parent_n = sum(1 for p, _ in groups if not p.parent_rule_id)
    child_n = sum(len(kids) for _, kids in groups) + sum(
        1 for p, _ in groups if p.parent_rule_id
    )
    section(
        f"Findings ({len(result.findings)})"
        + (f" — {parent_n} primary · {child_n} follow-up" if child_n else ""),
        _Style.BOLD,
    )
    if not groups:
        lines.append(_paint("  (none)", _Style.DIM, enabled=enabled))
    else:
        current_sev: Severity | None = None
        idx = 0
        for parent, kids in groups:
            idx += 1
            if parent.severity != current_sev and not parent.parent_rule_id:
                current_sev = parent.severity
                label = _paint(
                    parent.severity.value.upper(),
                    _SEVERITY_STYLE.get(parent.severity, ""),
                    enabled=enabled,
                )
                lines.append("")
                lines.append(f"  {label}")

            sev = _paint(
                f"[{parent.severity.value}]",
                _SEVERITY_STYLE.get(parent.severity, ""),
                enabled=enabled,
            )
            title = _paint(parent.title, _Style.BOLD, enabled=enabled)
            lines.append(f"  {idx}. {sev} {title}")
            meta = f"{parent.rule_id} · {parent.category}"
            if (parent.evidence or {}).get("escalation_ran"):
                meta += f" · +{len((parent.evidence or {}).get('escalation_children') or [])} follow-up"
            lines.append(f"     {_paint(meta, _Style.DIM, enabled=enabled)}")
            lines.append(f"     {parent.description}")
            show_impact = verbose or parent.severity in {
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
            }
            if show_impact and parent.impact:
                lines.append(
                    f"     {_paint('Impact', _Style.DIM, enabled=enabled)}  {parent.impact}"
                )
            if parent.remediation:
                lines.append(
                    f"     {_paint('Fix', _Style.GREEN, enabled=enabled)}     {parent.remediation}"
                )
            if verbose:
                parts = _evidence_parts(parent)
                if parts:
                    lines.append(
                        f"     {_paint('Evidence', _Style.DIM, enabled=enabled)} "
                        + "; ".join(parts)
                    )

            for kid in kids:
                idx += 1
                ksev = _paint(
                    f"[{kid.severity.value}]",
                    _SEVERITY_STYLE.get(kid.severity, ""),
                    enabled=enabled,
                )
                lines.append(
                    f"     ↳ {idx}. {ksev} {_paint(_child_title(kid), _Style.BOLD, enabled=enabled)}"
                )
                lines.append(
                    f"        {_paint(kid.rule_id, _Style.DIM, enabled=enabled)}  {kid.description}"
                )
                if kid.remediation and (
                    verbose
                    or kid.severity
                    in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
                ):
                    lines.append(
                        f"        {_paint('Fix', _Style.GREEN, enabled=enabled)}  {kid.remediation}"
                    )
                if verbose:
                    parts = _evidence_parts(kid, limit=60)
                    if parts:
                        lines.append(
                            f"        {_paint('Evidence', _Style.DIM, enabled=enabled)} "
                            + "; ".join(parts)
                        )

    if result.expected_surface:
        section("Expected surface", _Style.BOLD, _Style.BLUE)
        for f in result.expected_surface:
            bullet = _paint("·", _Style.BLUE, enabled=enabled)
            title = _paint(f.title, _Style.BOLD, enabled=enabled)
            lines.append(f"  {bullet} {title}: {f.description}")

    lines.append("")
    lines.append(rule)
    tip = "Tips: --html -o report.html · --json · --verbose (full evidence)"
    lines.append(_paint(tip, _Style.DIM, enabled=enabled))
    return "\n".join(lines).rstrip() + "\n"


def format_html_report(result: ScanResult) -> str:
    """Self-contained HTML report suitable for browsers and sharing."""
    summary = result.to_dict()["summary"]
    groups = _parent_groups(result.findings)
    esc = html.escape
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def sev_badge(sev: Severity) -> str:
        color = _SEVERITY_HEX.get(sev, "#64748b")
        return (
            f'<span class="badge" style="background:{color}">{esc(sev.value)}</span>'
        )

    def finding_card(finding: Finding, *, child: bool = False) -> str:
        cls = "finding child" if child else "finding"
        title = _child_title(finding) if child else finding.title
        bits = [
            f'<article class="{cls}">',
            '<div class="finding-head">',
            sev_badge(finding.severity),
            f"<h3>{esc(title)}</h3>",
            "</div>",
            f'<p class="meta">{esc(finding.rule_id)} · {esc(finding.category)} · '
            f"{esc(finding.confidence.value)}</p>",
            f"<p>{esc(finding.description)}</p>",
        ]
        if finding.impact:
            bits.append(
                f'<p class="impact"><strong>Impact</strong> {esc(finding.impact)}</p>'
            )
        if finding.remediation:
            bits.append(
                f'<p class="fix"><strong>Fix</strong> {esc(finding.remediation)}</p>'
            )
        parts = _evidence_parts(finding, limit=200)
        if parts:
            bits.append("<details><summary>Evidence</summary>")
            bits.append(f'<pre>{esc("; ".join(parts))}</pre>')
            bits.append("</details>")
        bits.append("</article>")
        return "\n".join(bits)

    summary_cells = []
    for name, key, sev in (
        ("Critical", "critical", Severity.CRITICAL),
        ("High", "high", Severity.HIGH),
        ("Medium", "medium", Severity.MEDIUM),
        ("Low", "low", Severity.LOW),
        ("Info", "info", Severity.INFO),
        ("Expected", "expected_surface", Severity.INFO),
    ):
        n = summary[key]
        summary_cells.append(
            f'<div class="stat"><span class="stat-n" style="color:{_SEVERITY_HEX.get(sev, "#64748b")}">'
            f'{n}</span><span class="stat-l">{name}</span></div>'
        )

    body_findings: list[str] = []
    if not groups:
        body_findings.append('<p class="empty">No findings.</p>')
    else:
        for parent, kids in groups:
            body_findings.append(finding_card(parent))
            for kid in kids:
                body_findings.append(finding_card(kid, child=True))

    expected_html = ""
    if result.expected_surface:
        items = "".join(
            f"<li><strong>{esc(f.title)}</strong> — {esc(f.description)}</li>"
            for f in result.expected_surface
        )
        expected_html = f"<section><h2>Expected surface</h2><ul class='expected'>{items}</ul></section>"

    errors_html = ""
    if result.errors:
        items = "".join(
            f"<li><code>{esc(e.code)}</code> {esc(e.message)}</li>" for e in result.errors
        )
        errors_html = f"<section class='errors'><h2>Errors</h2><ul>{items}</ul></section>"

    status = (
        f"ABORTED ({esc(result.abort_reason or '')})"
        if result.aborted
        else "completed"
    )
    chain_row = ""
    if result.network_name or result.chain_id is not None:
        chain_label = str(result.network_name or "unknown")
        if result.chain_id is not None:
            chain_label += f" ({result.chain_id})"
        chain_row = (
            f"<div><dt>Chain</dt><dd>{esc(chain_label)}</dd></div>"
        )
    client_row = (
        f"<div><dt>Client</dt><dd>{esc(result.client_version)}</dd></div>"
        if result.client_version
        else ""
    )
    provider_row = (
        f"<div><dt>Provider</dt><dd>{esc(result.provider)}</dd></div>"
        if result.provider
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Nodeprobe report — {esc(result.endpoint)}</title>
<style>
  :root {{
    --bg: #f6f4ef;
    --card: #ffffff;
    --ink: #1c1917;
    --muted: #78716c;
    --line: #e7e5e4;
    --accent: #0f766e;
    --fix: #166534;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font: 15px/1.5 "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
    color: var(--ink);
    background:
      radial-gradient(1200px 500px at 10% -10%, #d9f99d55, transparent),
      radial-gradient(900px 400px at 100% 0%, #99f6e455, transparent),
      var(--bg);
  }}
  main {{
    max-width: 880px;
    margin: 0 auto;
    padding: 2rem 1.25rem 4rem;
  }}
  header.hero {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 1.5rem 1.75rem;
    margin-bottom: 1.25rem;
  }}
  header.hero h1 {{
    margin: 0 0 0.35rem;
    font-size: 1.35rem;
    letter-spacing: -0.02em;
  }}
  header.hero .sub {{ color: var(--muted); font-size: 0.92rem; }}
  .score {{
    display: inline-block;
    margin-top: 0.75rem;
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.03em;
    color: {_score_hex(result.score)};
  }}
  dl.meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.65rem 1.25rem;
    margin: 1rem 0 0;
  }}
  dl.meta dt {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
  dl.meta dd {{ margin: 0.1rem 0 0; font-weight: 560; word-break: break-all; }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 0.5rem;
    margin: 1.25rem 0;
  }}
  @media (max-width: 720px) {{
    .stats {{ grid-template-columns: repeat(3, 1fr); }}
  }}
  .stat {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 0.75rem 0.5rem;
    text-align: center;
  }}
  .stat-n {{ display: block; font-size: 1.35rem; font-weight: 700; }}
  .stat-l {{ display: block; font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
  section h2 {{
    font-size: 1.05rem;
    margin: 1.5rem 0 0.75rem;
    letter-spacing: -0.01em;
  }}
  .finding {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 0.9rem 1rem;
    margin: 0.55rem 0;
  }}
  .finding.child {{
    margin-left: 1rem;
    border-left: 3px solid var(--accent);
    background: #fafaf9;
  }}
  .finding-head {{ display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }}
  .finding-head h3 {{ margin: 0; font-size: 1rem; }}
  .badge {{
    color: #fff;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding: 0.18rem 0.45rem;
    border-radius: 999px;
  }}
  .meta {{ color: var(--muted); font-size: 0.82rem; margin: 0.35rem 0 0.5rem; }}
  .fix strong {{ color: var(--fix); }}
  .impact strong {{ color: var(--muted); }}
  details {{ margin-top: 0.5rem; }}
  details summary {{ cursor: pointer; color: var(--muted); font-size: 0.85rem; }}
  pre {{
    margin: 0.4rem 0 0;
    padding: 0.65rem 0.75rem;
    background: #1c1917;
    color: #e7e5e4;
    border-radius: 8px;
    overflow-x: auto;
    font-size: 0.78rem;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  ul.expected {{ padding-left: 1.1rem; }}
  .errors {{ color: #991b1b; }}
  footer {{
    margin-top: 2rem;
    color: var(--muted);
    font-size: 0.82rem;
  }}
  .empty {{ color: var(--muted); }}
</style>
</head>
<body>
<main>
  <header class="hero">
    <h1>Nodeprobe scan report</h1>
    <p class="sub">Generated {esc(generated)} · scanner {esc(result.scanner_version)}</p>
    <div class="score">{result.score}/100</div>
    <dl class="meta">
      <div><dt>Target</dt><dd>{esc(result.endpoint)}</dd></div>
      <div><dt>Profile</dt><dd>{esc(result.profile.value)}</dd></div>
      <div><dt>Duration</dt><dd>{esc(_hr_duration(result.duration_ms))} · {result.requests_made} request(s)</dd></div>
      <div><dt>Status</dt><dd>{status}</dd></div>
      {chain_row}
      {client_row}
      {provider_row}
    </dl>
  </header>

  <div class="stats">
    {"".join(summary_cells)}
  </div>

  {errors_html}

  <section>
    <h2>Findings ({len(result.findings)})</h2>
    {"".join(body_findings)}
  </section>

  {expected_html}

  <footer>Local-first report from Nodeprobe. Authorized use only.</footer>
</main>
</body>
</html>
"""
