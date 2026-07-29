from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from dapptility_scanner import killswitch
from dapptility_scanner.chains import UnsupportedChainError, resolve_chain
from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.profiles import get_profile
from dapptility_scanner.providers import detect_provider
from dapptility_scanner.safety import UnsafeTargetError, mask_credentials, validate_target
from dapptility_scanner.scoring import compute_score
from dapptility_scanner.models import CheckKind, Confidence, Finding, Severity
from dapptility_scanner.cli import main


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
    import dapptility_scanner.safety as safety

    def fake_getaddrinfo(host, *args, **kwargs):
        return [(None, None, None, None, ("10.0.0.5", 0))]

    monkeypatch.setattr(safety.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeTargetError):
        validate_target("https://internal.example")


def test_supported_and_unsupported_chains():
    assert resolve_chain(1).name == "Ethereum Mainnet"
    with pytest.raises(UnsupportedChainError):
        resolve_chain(999999)


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
        if method.startswith(("debug_", "trace_", "personal_", "txpool_", "engine_")):
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


def test_unsupported_chain_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if body["method"] == "eth_chainId":
            return rpc_result(body["id"], "0xDEAD")  # 57005
        return rpc_error(body["id"], -32601, "the method does not exist")

    client = httpx.Client(transport=make_transport(handler))
    result = ScannerEngine(
        "https://rpc.example",
        "Free",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()
    assert result.aborted is True
    assert result.abort_reason == "unsupported_chain"
    assert any(e.code == "unsupported_chain" for e in result.errors)


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
