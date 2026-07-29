from __future__ import annotations

import httpx
import pytest

from dapptility_scanner import killswitch
from dapptility_scanner.http_client import BudgetedHttpClient
from dapptility_scanner.models import (
    CheckKind,
    Confidence,
    Finding,
    Severity,
)
from dapptility_scanner.profiles import get_profile
from dapptility_scanner.safety import SafeTarget
from dapptility_scanner.escalation_web import run_web_escalations
from dapptility_scanner.web_engine import WebScannerEngine


@pytest.fixture(autouse=True)
def _reset_killswitch():
    killswitch.reset()
    yield
    killswitch.reset()


def test_web_escalation_csp_and_server():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in {"/", ""}:
            return httpx.Response(
                200,
                text="<html><script>alert(1)</script><script>x()</script></html>",
                headers={"server": "nginx/1.25.0"},
            )
        if path == "/.env":
            return httpx.Response(200, text="SECRET_KEY=abc\nAPI_KEY=xyz\n")
        if path in {"/.well-known/security.txt", "/security.txt", "/robots.txt"}:
            return httpx.Response(404, text="no")
        return httpx.Response(404, text="no")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    result = WebScannerEngine(
        "https://site.example",
        "Standard",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert not result.aborted
    assert any(f.parent_rule_id == "WEB-HDR-001" for f in result.findings)
    # CSP missing should escalate framing / inline script next steps
    assert any("CSP" in f.title or "frame" in f.title.lower() or "inline script" in f.title.lower()
               for f in result.findings if f.parent_rule_id)
    # Server disclosure may escalate to .env hit
    assert any(
        f.parent_rule_id == "WEB-HDR-002" and f.severity == Severity.HIGH
        for f in result.findings
    ) or any("sensitive path" in f.title.lower() for f in result.findings)


def test_web_escalation_skipped_on_quick():
    parent = Finding(
        rule_id="WEB-HDR-001",
        title="Missing HSTS header",
        category="HTTP Security",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        description="missing",
        evidence={"header": "strict-transport-security"},
        score_impact=12,
    )
    target = SafeTarget(
        original_url="https://site.example",
        sanitized_url="https://site.example",
        hostname="site.example",
        port=443,
        scheme="https",
        resolved_ips=["1.2.3.4"],
    )
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")))
    client = BudgetedHttpClient(target, get_profile("Quick"), client=http)
    kids = run_web_escalations(client, {"primary": None}, [parent])
    client.close()
    assert kids == []
