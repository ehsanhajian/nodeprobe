from __future__ import annotations

import json

import httpx
import pytest

from dapptility_scanner import killswitch
from dapptility_scanner.contract_engine import ContractScannerEngine
from dapptility_scanner.escalation_contract import run_contract_escalations
from dapptility_scanner.models import (
    CheckKind,
    Confidence,
    Finding,
    Severity,
)
from dapptility_scanner.profiles import get_profile
from dapptility_scanner.rpc import RpcClient
from dapptility_scanner.safety import SafeTarget


@pytest.fixture(autouse=True)
def _reset_killswitch():
    killswitch.reset()
    yield
    killswitch.reset()


EIP1167_CODE = (
    "0x"
    + "363d3d373d3d3d363d73"
    + "1111111111111111111111111111111111111111"
    + "5af43d82803e903d91602b57fd5bf3"
)

IMPL_CODE = "0x5bff"  # JUMPDEST + SELFDESTRUCT


def test_contract_proxy_escalation_fetches_impl(monkeypatch):
    address = "0x2222222222222222222222222222222222222222"
    impl = "0x1111111111111111111111111111111111111111"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body.get("method")
        req_id = body.get("id", 1)
        if method == "eth_chainId":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x1"})
        if method == "eth_getCode":
            params = body.get("params") or []
            target = (params[0] or "").lower()
            if target == impl:
                code = IMPL_CODE
            else:
                code = EIP1167_CODE
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": req_id, "result": code}
            )
        if method == "eth_getStorageAt":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x" + ("00" * 32)}
            )
        if method == "eth_call":
            # owner() → 0xbbbb...
            result = "0x" + ("00" * 12) + ("bb" * 20)
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": req_id, "result": result}
            )
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "no"}},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    monkeypatch.setattr(
        "dapptility_scanner.contract_engine.fetch_sourcify",
        lambda *a, **k: type(
            "M",
            (),
            {
                "status": "not_found",
                "chain_id": 1,
                "address": address,
                "abi": None,
                "contract_name": None,
                "compiler": None,
                "raw": None,
            },
        )(),
    )

    result = ContractScannerEngine(
        address,
        rpc_url="https://rpc.example",
        chain_id=1,
        profile="Standard",
        http_client=client,
        resolve_dns=False,
        fetch_verification=True,
    ).run()
    client.close()

    assert not result.aborted
    assert any(f.parent_rule_id == "SC-PROXY-001" for f in result.findings)
    assert any("implementation" in f.title.lower() or "SELFDESTRUCT" in f.title for f in result.findings if f.parent_rule_id)


def test_contract_ownable_escalation_unit():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        req_id = body.get("id", 1)
        if body.get("method") == "eth_call":
            result = "0x" + ("00" * 12) + ("aa" * 20)
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": req_id, "result": result}
            )
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "no"}},
        )

    http = httpx.Client(transport=httpx.MockTransport(handler))
    target = SafeTarget(
        original_url="https://rpc.example",
        sanitized_url="https://rpc.example",
        hostname="rpc.example",
        port=443,
        scheme="https",
        resolved_ips=["1.2.3.4"],
    )
    rpc = RpcClient(target, get_profile("Standard"), client=http)
    parent = Finding(
        rule_id="SC-IFACE-002",
        title="Ownable-style ownership surface",
        category="Access Control",
        severity=Severity.INFO,
        confidence=Confidence.LIKELY,
        kind=CheckKind.FINDING,
        description="ownable",
        score_impact=2,
    )
    kids = run_contract_escalations(
        rpc,
        address="0x2222222222222222222222222222222222222222",
        findings=[parent],
    )
    rpc.close()
    http.close()
    assert kids
    assert kids[0].parent_rule_id == "SC-IFACE-002"
    assert "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in kids[0].title
