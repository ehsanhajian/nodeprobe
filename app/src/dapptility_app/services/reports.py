from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from dapptility_app.config import settings
from dapptility_app.database import Endpoint, Finding, Project, Report, Scan

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"
env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


SCOPE_DID = [
    "External HTTP JSON-RPC assessment from an attacker's perspective",
    "Chain ID, client version, TLS, HTTP headers, and namespace presence probes",
    "Expected public RPC surface labeled separately from security findings",
]

SCOPE_DID_NOT = [
    "No exploitation or proof-of-compromise actions",
    "No broad port scanning or public load testing",
    "No expensive debug/trace payloads on Quick or Standard profiles",
    "No access to internal infrastructure, agents, or credentials",
]

MODULE_SCOPE: dict[str, dict[str, list[str]]] = {
    "web": {
        "did": [
            "External website HTTP/TLS posture checks",
            "Security headers, certificate validity, security.txt / robots.txt",
            "Server technology disclosure observation",
        ],
        "did_not": [
            "No authenticated crawling or form submission",
            "No exploitation or intrusive vulnerability probing",
            "No deep application fuzzing",
        ],
    },
    "rpc": {
        "did": [
            "External HTTP JSON-RPC assessment from an attacker's perspective",
            "Chain ID, client version, TLS, HTTP headers, and namespace presence probes",
            "Expected public RPC surface labeled separately from security findings",
        ],
        "did_not": [
            "No exploitation or proof-of-compromise actions",
            "No expensive debug/trace payloads on Quick or Standard profiles",
            "No access to internal infrastructure, agents, or credentials",
        ],
    },
    "contract": {
        "did": [
            "Read-only on-chain inspection via eth_getCode / eth_getStorageAt",
            "Proxy pattern hints (EIP-1967 / 1822 / 1167)",
            "Bytecode heuristics and optional Sourcify verification enrichment",
        ],
        "did_not": [
            "No transaction broadcast or state-changing calls",
            "No full symbolic execution or auto-exploitation",
            "No guarantee of verified source correctness beyond Sourcify match status",
        ],
    },
}


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def scope_for_modules(modules: list[str] | None) -> tuple[list[str], list[str]]:
    if not modules:
        return SCOPE_DID, SCOPE_DID_NOT
    did: list[str] = []
    did_not: list[str] = []
    for module in modules:
        block = MODULE_SCOPE.get(module)
        if not block:
            continue
        for item in block["did"]:
            labeled = f"[{module}] {item}"
            if labeled not in did:
                did.append(labeled)
        for item in block["did_not"]:
            labeled = f"[{module}] {item}"
            if labeled not in did_not:
                did_not.append(labeled)
    return did or SCOPE_DID, did_not or SCOPE_DID_NOT


def render_report_html(
    *,
    project: Project,
    endpoint: Endpoint,
    scan: Scan,
    findings: list[Finding],
    report: Report,
    module_summaries: list[dict[str, Any]] | None = None,
) -> str:
    modules = [m["module"] for m in (module_summaries or []) if m.get("module")]
    if not modules and (scan.module or (endpoint.kind if endpoint else None)):
        modules = [scan.module or endpoint.kind]
    scope_did, scope_did_not = scope_for_modules(modules if report.report_type == "project" else None)
    if report.report_type != "project":
        # Single-module report: use module-specific scope when known
        mod = (scan.module or endpoint.kind or "rpc").lower()
        if mod in MODULE_SCOPE:
            scope_did, scope_did_not = scope_for_modules([mod])

    scores = [m["score"] for m in (module_summaries or []) if m.get("score") is not None]
    overall_score = min(scores) if scores else scan.score

    template = env.get_template("report.html")
    return template.render(
        project=project,
        endpoint=endpoint,
        scan=scan,
        findings=findings,
        report=report,
        module_summaries=module_summaries or [],
        overall_score=overall_score,
        scope_did=scope_did,
        scope_did_not=scope_did_not,
        severity_counts=_severity_counts(findings),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        report_url=f"{settings.report_base_url.rstrip('/')}/r/{report.token}",
    )


def _pdf_safe(text: str) -> str:
    cleaned = text.replace("*", "x")
    return cleaned.encode("latin-1", "replace").decode("latin-1")


def _pdf_line(pdf, width: float, text: str, *, height: float = 5) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(width, height, _pdf_safe(text))


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_pdf(
    *,
    project: Project,
    endpoint: Endpoint,
    scan: Scan,
    findings: list[Finding],
    report: Report,
    output_path: Path,
    module_summaries: list[dict[str, Any]] | None = None,
) -> None:
    from fpdf import FPDF

    modules = [m["module"] for m in (module_summaries or []) if m.get("module")]
    if report.report_type == "project":
        scope_did, scope_did_not = scope_for_modules(modules)
    else:
        mod = (scan.module or endpoint.kind or "rpc").lower()
        scope_did, scope_did_not = scope_for_modules([mod] if mod in MODULE_SCOPE else None)

    scores = [m["score"] for m in (module_summaries or []) if m.get("score") is not None]
    overall_score = min(scores) if scores else scan.score

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _pdf_safe("Dapptility Security Report"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, _pdf_safe(report.title), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.cell(0, 6, _pdf_safe(f"Project: {project.name}"), new_x="LMARGIN", new_y="NEXT")
    if report.report_type == "project" and module_summaries:
        for item in module_summaries:
            pdf.cell(
                0,
                6,
                _pdf_safe(
                    f"[{item['module']}] {item.get('label', '')} — score {item.get('score', '—')}"
                ),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        pdf.cell(0, 6, _pdf_safe(f"Overall (min module score): {overall_score}/100"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, _pdf_safe(f"Target: {endpoint.label}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, _pdf_safe(f"Profile: {scan.profile}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, _pdf_safe(f"Score: {scan.score}/100"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(
            0,
            6,
            _pdf_safe(f"Chain: {scan.network_name or 'unknown'} ({scan.chain_id})"),
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _pdf_safe("What we did / What we did not do"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for item in scope_did:
        _pdf_line(pdf, width, f"- {item}")
    for item in scope_did_not:
        _pdf_line(pdf, width, f"- NOT: {item}")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _pdf_safe("Findings"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if not findings:
        pdf.cell(0, 6, _pdf_safe("No publishable findings."), new_x="LMARGIN", new_y="NEXT")
    for f in findings:
        pdf.set_font("Helvetica", "B", 10)
        module = getattr(f, "module", None) or ""
        prefix = f"[{module}] " if module else ""
        _pdf_line(pdf, width, f"{prefix}[{f.severity}] {f.title} ({f.rule_id})")
        pdf.set_font("Helvetica", "", 10)
        _pdf_line(pdf, width, f.description)
        if f.remediation:
            _pdf_line(pdf, width, f"Remediation: {f.remediation}")
        pdf.ln(2)

    pdf.output(str(output_path))
