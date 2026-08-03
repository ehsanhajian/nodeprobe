from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from nodeprobe import killswitch
from nodeprobe.chains import resolve_chain
from nodeprobe.engine import ScannerEngine
from nodeprobe.profiles import get_profile
from nodeprobe.providers import detect_provider
from nodeprobe.safety import UnsafeTargetError, mask_credentials, validate_target
from nodeprobe.scoring import compute_score
from nodeprobe.models import CheckKind, Confidence, Finding, Severity
from nodeprobe.cli import main


def make_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def rpc_result(req_id: int, result: Any) -> httpx.Response:
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": req_id, "result": result},
        headers={"content-type": "application/json", "server": "nginx/1.24.0"},
    )


def rpc_error(req_id: int, code: int, message: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        },
        headers={"content-type": "application/json"},
    )


@pytest.fixture(autouse=True)
def _reset_killswitch():
    killswitch.reset()
    yield
    killswitch.reset()


def test_mask_credentials():
    assert "***@" in mask_credentials("https://user:secret@rpc.example/path")
    assert "[redacted]" in mask_credentials("https://rpc.example/?apiKey=abc")


def test_validate_blocks_localhost():
    with pytest.raises(UnsafeTargetError):
        validate_target("http://localhost:8545")
    with pytest.raises(UnsafeTargetError):
        validate_target("http://127.0.0.1:8545")
    with pytest.raises(UnsafeTargetError):
        validate_target("http://169.254.169.254/latest/meta-data")


def test_validate_blocks_private_hostname_resolution(monkeypatch):
    import nodeprobe.safety as safety

    def fake_getaddrinfo(host, *args, **kwargs):
        return [(None, None, None, None, ("10.0.0.5", 0))]

    monkeypatch.setattr(safety.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeTargetError):
        validate_target("https://internal.example")


def test_resolve_any_chain():
    assert resolve_chain(1).name == "Ethereum Mainnet"
    assert resolve_chain(592).name == "Astar"
    unknown = resolve_chain(999999001)
    assert unknown.name == "Chain 999999001"
    assert unknown.listed is False


def test_provider_detection():
    match = detect_provider("https://eth-mainnet.g.alchemy.com/v2/demo")
    assert match is not None
    assert match.provider == "Alchemy"
    assert detect_provider("https://rpc.myproject.xyz") is None


def test_profiles():
    quick = get_profile("Quick")
    assert quick.max_requests == 40
    assert quick.max_rps == 2.0
    assert get_profile("Free").name.value == "Quick"
    standard = get_profile("outbound")
    assert standard.name.value == "Standard"
    assert standard.max_rps == 3.0
    deep = get_profile("Authorized-Full")
    assert deep.name.value == "Deep"
    assert deep.max_requests == 200


def test_scoring_critical_caps():
    findings = [
        Finding(
            rule_id="x",
            title="t",
            category="c",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            kind=CheckKind.FINDING,
            description="d",
            score_impact=35,
        )
    ]
    assert compute_score(findings) <= 40


def test_scan_happy_path_with_admin_exposure():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "eth_chainId":
            return rpc_result(req_id, "0x1")
        if method == "net_version":
            return rpc_result(req_id, "1")
        if method == "eth_blockNumber":
            return rpc_result(req_id, "0x10")
        if method == "web3_clientVersion":
            return rpc_result(req_id, "Geth/v1.13.0")
        if method == "admin_nodeInfo":
            return rpc_result(req_id, {"name": "node"})
        if method.startswith(("debug_", "trace_", "personal_", "txpool_", "engine_", "miner_", "clique_")):
            return rpc_error(req_id, -32601, "the method does not exist")
        if method in {"eth_accounts", "rpc_modules"}:
            return rpc_error(req_id, -32601, "the method does not exist")
        if method in {"eth_getBalance", "eth_call"}:
            return rpc_result(req_id, "0x0")
        if method == "eth_sendRawTransaction":
            return rpc_error(req_id, -32602, "invalid raw transaction")
        return rpc_error(req_id, -32601, "the method does not exist")

    transport = make_transport(handler)
    client = httpx.Client(transport=transport, base_url="https://rpc.example")
    # Point URL at host that won't DNS for TLS — skip TLS probe
    result = ScannerEngine(
        "https://rpc.example/v1",
        "Free",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert result.chain_id == 1
    assert result.network_name == "Ethereum Mainnet"
    assert result.aborted is False
    assert any(f.rule_id == "EVM-NS-ADMIN" for f in result.findings)
    assert any(f.kind.value == "expected_surface" for f in result.expected_surface)
    assert result.score <= 40
    payload = result.to_dict()
    assert "summary" in payload
    assert payload["summary"]["critical"] >= 1


def test_unknown_chain_still_scans():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "eth_chainId":
            return rpc_result(req_id, "0xDEAD")  # 57005 — unlikely listed
        if method == "net_version":
            return rpc_result(req_id, "57005")
        if method == "eth_blockNumber":
            return rpc_result(req_id, "0x10")
        if method == "web3_clientVersion":
            return rpc_result(req_id, "Geth/v1.13.0")
        return rpc_error(req_id, -32601, "the method does not exist")

    client = httpx.Client(transport=make_transport(handler))
    result = ScannerEngine(
        "https://rpc.example",
        "Free",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()
    assert result.aborted is False
    assert result.chain_id == 57005
    assert result.network_name  # name from registry or Chain 57005
    assert not any(e.code == "unsupported_chain" for e in result.errors)


def test_block_providers_flag():
    result = ScannerEngine(
        "https://eth-mainnet.g.alchemy.com/v2/demo",
        "Standard",
        block_providers=True,
    ).run()
    assert result.aborted is True
    assert result.abort_reason == "third_party_provider"
    assert result.provider == "Alchemy"

    # Without the flag, Standard does not auto-block (personal tool)
    allowed = ScannerEngine(
        "https://eth-mainnet.g.alchemy.com/v2/demo",
        "Standard",
        block_providers=False,
        skip_tls_probe=True,
        resolve_dns=False,
    )
    # Still constructs; run may fail on network — only assert provider detection path with flag above
    assert allowed.block_providers is False


def test_kill_switch_aborts():
    killswitch.force_kill(True)
    result = ScannerEngine("https://rpc.example", "Quick", skip_tls_probe=True).run()
    assert result.aborted is True
    assert result.abort_reason == "kill_switch"


def test_cli_profiles(capsys):
    assert main(["profiles"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "Quick" in data
    assert data["Quick"]["max_requests"] == 40
    assert "Standard" in data
    assert "Deep" in data
    assert "Free" not in data


def test_cli_rules(capsys):
    assert main(["rules"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) >= 10
    ids = {r["rule_id"] for r in data}
    assert "EVM-IDENT-001" in ids
    assert "EVM-NS-ADMIN" in ids
    assert "EVM-CLIENT-003" in ids
    assert "EVM-RATE-001" in ids


def test_human_report_format():
    from nodeprobe.models import ScanProfile, ScanResult
    from nodeprobe.report import format_human_report

    result = ScanResult(
        scanner_version="0.1.0",
        profile=ScanProfile.QUICK,
        endpoint="https://example.com",
        started_at="t0",
        finished_at="t1",
        duration_ms=1500,
        requests_made=4,
        chain_id=None,
        network_name=None,
        client_version=None,
        score=54,
        findings=[
            Finding(
                rule_id="WEB-HDR-001",
                title="Missing HSTS header",
                category="HTTP Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                kind=CheckKind.FINDING,
                description="Response does not include HSTS.",
                impact="Downgrade risk.",
                remediation="Set Strict-Transport-Security.",
                evidence={"header": "strict-transport-security"},
                score_impact=12,
            )
        ],
        expected_surface=[],
        errors=[],
    )
    text = format_human_report(result, color=False)
    assert "Nodeprobe scan report" in text
    assert "Score" in text and "54/100" in text
    assert "[Medium] Missing HSTS header" in text
    assert "Fix" in text and "Set Strict-Transport-Security." in text
    assert "Evidence" not in text  # compact by default
    assert "\033[" not in text

    verbose = format_human_report(result, color=False, verbose=True)
    assert "Evidence" in verbose
    assert "header=" in verbose

    colored = format_human_report(result, color=True)
    assert "\033[" in colored
    assert "54/100" in colored
    assert "[Medium]" in colored


def test_html_report_format(tmp_path):
    from nodeprobe.models import ScanProfile, ScanResult
    from nodeprobe.report import format_html_report

    result = ScanResult(
        scanner_version="0.1.0",
        profile=ScanProfile.STANDARD,
        endpoint="https://example.com",
        started_at="t0",
        finished_at="t1",
        duration_ms=2100,
        requests_made=6,
        chain_id=None,
        network_name=None,
        client_version=None,
        score=37,
        findings=[
            Finding(
                rule_id="WEB-HDR-001",
                title="Missing CSP header",
                category="HTTP Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                kind=CheckKind.FINDING,
                description="No CSP.",
                remediation="Set CSP.",
                score_impact=10,
            ),
            Finding(
                rule_id="WEB-HDR-001-NEXT",
                title="Next: no frame controls",
                category="Escalation",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                kind=CheckKind.FINDING,
                description="Framing open.",
                parent_rule_id="WEB-HDR-001",
                score_impact=8,
            ),
        ],
        expected_surface=[],
        errors=[],
    )
    doc = format_html_report(result)
    assert "<!DOCTYPE html>" in doc
    assert "Missing CSP header" in doc
    assert "no frame controls" in doc
    assert "37/100" in doc
    assert "finding child" in doc
    path = tmp_path / "report.html"
    path.write_text(doc, encoding="utf-8")
    assert path.stat().st_size > 500


def test_cli_scan_json_flag(capsys, monkeypatch):
    from nodeprobe.models import ScanProfile, ScanResult

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run(self):
            return ScanResult(
                scanner_version="0.1.0",
                profile=ScanProfile.QUICK,
                endpoint="https://rpc.example",
                started_at="t0",
                finished_at="t1",
                duration_ms=1,
                requests_made=1,
                chain_id=1,
                network_name="Ethereum Mainnet",
                client_version=None,
                score=100,
                findings=[],
                expected_surface=[],
                errors=[],
            )

    monkeypatch.setattr("nodeprobe.cli.ScannerEngine", FakeEngine)
    assert main(["scan", "https://rpc.example"]) == 0
    human = capsys.readouterr().out
    assert "Nodeprobe scan report" in human

    assert main(["scan", "https://rpc.example", "--json", "--pretty"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["endpoint"] == "https://rpc.example"
    assert payload["score"] == 100


def _rich_rpc_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content.decode())
    method = body["method"]
    req_id = body["id"]
    if method == "eth_chainId":
        return rpc_result(req_id, "0x1")
    if method == "net_version":
        return rpc_result(req_id, "1")
    if method == "eth_blockNumber":
        return rpc_result(req_id, "0x10")
    if method == "eth_gasPrice":
        return rpc_result(req_id, "0x1")
    if method == "web3_clientVersion":
        return rpc_result(req_id, "Geth/v1.10.26-stable")
    if method == "rpc_modules":
        return rpc_result(req_id, {"eth": "1.0", "net": "1.0", "debug": "1.0", "admin": "1.0"})
    if method == "admin_nodeInfo":
        return rpc_result(req_id, {"name": "node"})
    if method == "debug_traceBlockByNumber":
        return rpc_error(req_id, -32602, "missing value")
    if method == "debug_memStats":
        return rpc_result(req_id, {"HeapAlloc": 1})
    if method == "eth_accounts":
        return rpc_result(req_id, [])
    if method.startswith(("trace_", "personal_", "txpool_", "engine_", "miner_", "clique_")):
        return rpc_error(req_id, -32601, "the method does not exist")
    if method in {"eth_getBalance", "eth_call"}:
        return rpc_result(req_id, "0x0")
    if method == "eth_sendRawTransaction":
        return rpc_error(req_id, -32602, "invalid raw transaction")
    return rpc_error(req_id, -32601, "the method does not exist")


def test_deep_richer_than_quick():
    quick_client = httpx.Client(transport=make_transport(_rich_rpc_handler))
    deep_client = httpx.Client(transport=make_transport(_rich_rpc_handler))

    quick = ScannerEngine(
        "https://rpc.example/v1",
        "Quick",
        http_client=quick_client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    deep = ScannerEngine(
        "https://rpc.example/v1",
        "Deep",
        http_client=deep_client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    quick_client.close()
    deep_client.close()

    assert not quick.aborted and not deep.aborted
    quick_ids = {f.rule_id for f in quick.findings}
    deep_ids = {f.rule_id for f in deep.findings}
    assert "EVM-NS-ADMIN" in quick_ids
    assert "EVM-CLIENT-003" not in quick_ids  # Deep-only
    assert "EVM-RATE-001" not in quick_ids
    assert "EVM-CLIENT-003" in deep_ids
    assert "EVM-RATE-001" in deep_ids or any(
        f.rule_id == "EVM-RATE-001" for f in deep.findings + deep.expected_surface
    )
    # Deep client fingerprint elevates old Geth
    assert any(
        f.rule_id == "EVM-CLIENT-001" and f.severity.value == "Medium" for f in deep.findings
    )
    assert deep.requests_made > quick.requests_made
    # Deep debug confirm path
    debug = next(f for f in deep.findings if f.rule_id == "EVM-NS-DEBUG")
    assert debug.evidence.get("deep_confirm_available") is True


def test_provider_informational_when_not_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return _rich_rpc_handler(request)

    client = httpx.Client(transport=make_transport(handler))
    result = ScannerEngine(
        "https://eth-mainnet.g.alchemy.com/v2/demo",
        "Quick",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
        block_providers=False,
    ).run()
    client.close()
    assert not result.aborted
    assert any(f.rule_id == "EVM-PROV-001" for f in result.findings)
