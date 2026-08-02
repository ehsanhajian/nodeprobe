from __future__ import annotations

import httpx
import pytest

from nodeprobe import killswitch
from nodeprobe.models import Severity
from nodeprobe.web_engine import WebScannerEngine


@pytest.fixture(autouse=True)
def _reset_killswitch():
    killswitch.reset()
    yield
    killswitch.reset()


def test_web_scan_grades_weak_hsts_and_csp():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in {"/", ""}:
            return httpx.Response(
                200,
                text="<html><script>x=1</script></html>",
                headers={
                    "strict-transport-security": "max-age=60",
                    "content-security-policy": "default-src *; script-src 'unsafe-inline'",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                    "x-frame-options": "DENY",
                },
            )
        if path in {"/.well-known/security.txt", "/security.txt", "/robots.txt"}:
            return httpx.Response(404, text="missing")
        return httpx.Response(404, text="nope")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    result = WebScannerEngine(
        "https://site.example",
        "Quick",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert not result.aborted
    ids = {f.rule_id for f in result.findings}
    assert "WEB-HDR-003" in ids
    assert "WEB-HDR-004" in ids
    assert any("max-age" in f.title.lower() for f in result.findings if f.rule_id == "WEB-HDR-003")
    assert any(
        f.rule_id == "WEB-HDR-004" and f.severity in {Severity.HIGH, Severity.MEDIUM}
        for f in result.findings
    )
