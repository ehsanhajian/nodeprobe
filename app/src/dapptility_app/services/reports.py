from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

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
    "No expensive debug/trace payloads on Free or Outbound profiles",
    "No access to internal infrastructure, agents, or credentials",
]


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def render_report_html(
    *,
    project: Project,
    endpoint: Endpoint,
    scan: Scan,
    findings: list[Finding],
    report: Report,
) -> str:
    template = env.get_template("report.html")
    return template.render(
        project=project,
        endpoint=endpoint,
        scan=scan,
        findings=findings,
        report=report,
        scope_did=SCOPE_DID,
        scope_did_not=SCOPE_DID_NOT,
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
) -> None:
    from fpdf import FPDF

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
    pdf.cell(0, 6, _pdf_safe(f"Endpoint: {endpoint.url}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _pdf_safe(f"Profile: {scan.profile}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _pdf_safe(f"Score: {scan.score}/100"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _pdf_safe(f"Chain: {scan.network_name or 'unknown'} ({scan.chain_id})"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _pdf_safe("What we did / What we did not do"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for item in SCOPE_DID:
        _pdf_line(pdf, width, f"- {item}")
    for item in SCOPE_DID_NOT:
        _pdf_line(pdf, width, f"- NOT: {item}")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _pdf_safe("Findings"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if not findings:
        pdf.cell(0, 6, _pdf_safe("No publishable findings."), new_x="LMARGIN", new_y="NEXT")
    for f in findings:
        pdf.set_font("Helvetica", "B", 10)
        _pdf_line(pdf, width, f"[{f.severity}] {f.title} ({f.rule_id})")
        pdf.set_font("Helvetica", "", 10)
        _pdf_line(pdf, width, f.description)
        if f.remediation:
            _pdf_line(pdf, width, f"Remediation: {f.remediation}")
        pdf.ln(2)

    pdf.output(str(output_path))
