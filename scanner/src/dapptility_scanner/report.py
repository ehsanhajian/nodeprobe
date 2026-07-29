"""Human-readable scan report formatting."""

from __future__ import annotations

import os
import sys

from dapptility_scanner.models import Finding, ScanResult, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
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


def format_human_report(result: ScanResult, *, color: bool | None = None) -> str:
    enabled = use_color(force=color)
    summary = result.to_dict()["summary"]
    lines: list[str] = []

    def row(key: str, value: str) -> str:
        return f"{_paint(f'{key}:', _Style.DIM, enabled=enabled)}  {value}"

    def section(title: str, *styles: str) -> None:
        lines.append(_paint(title, *styles, enabled=enabled))
        lines.append(_paint("-" * 72, _Style.DIM, enabled=enabled))

    rule = _paint("=" * 72, _Style.DIM, enabled=enabled)
    lines.append(
        _paint("Dapptility scan report", _Style.BOLD, _Style.BRIGHT_CYAN, enabled=enabled)
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
        lines.append(row("Chain", f"{chain} ({result.chain_id})"))
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

    lines.append("")
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
        f"Expected-surface {_paint(str(summary['expected_surface']), _Style.DIM, enabled=enabled)}"
    )
    lines.append("  " + "  ".join(bits))

    if result.errors:
        lines.append("")
        section("Errors", _Style.BOLD, _Style.BRIGHT_RED)
        for err in result.errors:
            code = _paint(f"[{err.code}]", _Style.RED, enabled=enabled)
            lines.append(f"  {code} {err.message}")

    findings = _ordered_findings(result.findings)
    lines.append("")
    section(f"Findings ({len(findings)})", _Style.BOLD)
    if not findings:
        lines.append(_paint("  (none)", _Style.DIM, enabled=enabled))
    else:
        for i, f in enumerate(findings, 1):
            sev = _paint(
                f"[{f.severity.value}]",
                _SEVERITY_STYLE.get(f.severity, ""),
                enabled=enabled,
            )
            prefix = "   ↳ " if f.parent_rule_id else ""
            title = f.title
            if f.parent_rule_id:
                title = f"Next step · {f.title}" if not f.title.lower().startswith("next") else f.title
            lines.append(
                f"{prefix}{i}. {sev} {_paint(title, _Style.BOLD, enabled=enabled)}"
            )
            meta = f"{f.rule_id} · {f.category} · {f.confidence.value}"
            if f.parent_rule_id:
                meta += f" · from {f.parent_rule_id}"
            elif (f.evidence or {}).get("escalation_ran"):
                kids = (f.evidence or {}).get("escalation_children") or []
                meta += f" · escalated → {', '.join(kids)}"
            lines.append(
                f"{'     ' if f.parent_rule_id else '   '}"
                f"{_paint(meta, _Style.DIM, enabled=enabled)}"
            )
            indent = "      " if f.parent_rule_id else "   "
            lines.append(f"{indent}{f.description}")
            if f.impact:
                lines.append(
                    f"{indent}{_paint('Impact:', _Style.DIM, enabled=enabled)} {f.impact}"
                )
            if f.remediation:
                lines.append(
                    f"{indent}{_paint('Fix:', _Style.GREEN, enabled=enabled)}    {f.remediation}"
                )
            if f.evidence:
                parts = []
                for key_name, value in f.evidence.items():
                    if key_name in {"escalation_ran", "escalation_children"}:
                        continue
                    text = str(value)
                    if len(text) > 80:
                        text = text[:77] + "..."
                    parts.append(f"{key_name}={text}")
                if parts:
                    lines.append(
                        f"{indent}{_paint('Evidence:', _Style.DIM, enabled=enabled)} {'; '.join(parts)}"
                    )
            lines.append("")

    if result.expected_surface:
        section(
            "Expected surface (not scored as vulnerabilities)",
            _Style.BOLD,
            _Style.BLUE,
        )
        for f in result.expected_surface:
            bullet = _paint("·", _Style.BLUE, enabled=enabled)
            title = _paint(f.title, _Style.BOLD, enabled=enabled)
            lines.append(f"  {bullet} {title}: {f.description}")
        lines.append("")

    lines.append(rule)
    lines.append(
        _paint("Tip: use --json for machine-readable output.", _Style.DIM, enabled=enabled)
    )
    return "\n".join(lines).rstrip() + "\n"
