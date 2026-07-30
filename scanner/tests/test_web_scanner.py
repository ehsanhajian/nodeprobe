from __future__ import annotations

import httpx
import pytest

from nodeprobe import killswitch
from nodeprobe.cli import main
from nodeprobe.models import ScanProfile, ScanResult
from nodeprobe.web_engine import WebScannerEngine


@pytest.fixture(autouse=True)
def _reset_killswitch():
    killswitch.reset()
    yield
    killswitch.reset()


def test_web_scan_headers_and_well_known():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in {"/", ""}:
            return httpx.Response(
                200,
                text="<html><title>Demo</title></html>",
                headers={
                    "server": "nginx/1.25.0",
                    "x-content-type-options": "nosniff",
                },
            )
        if path == "/.well-known/security.txt":
            return httpx.Response(404, text="missing")
        if path == "/security.txt":
            return httpx.Response(404, text="missing")
        if path == "/robots.txt":
            return httpx.Response(
                200,
                text="User-agent: *\nDisallow: /admin/\nDisallow: /api/internal\n",
            )
        return httpx.Response(404, text="nope")

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, follow_redirects=False)

    result = WebScannerEngine(
        "https://site.example",
        "Free",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()

    assert not result.aborted
    finding_ids = {f.rule_id for f in result.findings}
    assert "WEB-HDR-001" in finding_ids
    assert "WEB-HDR-002" in finding_ids
    assert "WEB-WKN-001" in finding_ids
    assert "WEB-WKN-002" in finding_ids
    assert result.requests_made >= 3


def test_cli_web_and_rules(capsys, monkeypatch):
    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run(self):
            return ScanResult(
                scanner_version="0.1.0",
                profile=ScanProfile.QUICK,
                endpoint="https://example.com",
                started_at="t0",
                finished_at="t1",
                duration_ms=1,
                requests_made=1,
                chain_id=None,
                network_name=None,
                client_version=None,
                score=90,
                findings=[],
                expected_surface=[],
                errors=[],
            )

    monkeypatch.setattr("nodeprobe.cli.WebScannerEngine", FakeEngine)
    assert main(["web", "https://example.com"]) == 0
    out = capsys.readouterr().out
    assert "Nodeprobe scan report" in out
    assert "https://example.com" in out
    assert "Score:" in out

    assert main(["web", "https://example.com", "--json"]) == 0
    json_out = capsys.readouterr().out
    assert '"endpoint": "https://example.com"' in json_out

    assert main(["rules", "--module", "web"]) == 0
    rules_out = capsys.readouterr().out
    assert "WEB-TLS-001" in rules_out
    assert "WEB-HDR-001" in rules_out
