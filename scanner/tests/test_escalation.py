from __future__ import annotations

import json
from typing import Any

import httpx

from nodeprobe.engine import ScannerEngine
from nodeprobe.escalation import run_evm_escalations
from nodeprobe.models import (
    CheckKind,
    Confidence,
    Finding,
    ScanProfile,
    Severity,
)
from nodeprobe.profiles import get_profile
from nodeprobe.rpc import RpcClient
from nodeprobe.safety import SafeTarget


def make_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def rpc_result(req_id: int, result: Any) -> httpx.Response:
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": req_id, "result": result},
        headers={"content-type": "application/json"},
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


def test_escalation_eth_accounts_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        return rpc_result(body["id"], [])

    client = httpx.Client(transport=make_transport(handler))
    target = SafeTarget(
        original_url="https://rpc.example",
        sanitized_url="https://rpc.example",
        hostname="rpc.example",
        port=443,
        scheme="https",
        resolved_ips=["1.2.3.4"],
    )
    rpc = RpcClient(target, get_profile("Standard"), client=client)
    parent = Finding(
        rule_id="EVM-NS-ACCOUNTS",
        title="Exposed eth_accounts",
        category="RPC Method Exposure",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        description="present",
        score_impact=20,
    )
    kids = run_evm_escalations(rpc, {}, [parent])
    rpc.close()
    client.close()
    assert kids
    assert kids[0].parent_rule_id == "EVM-NS-ACCOUNTS"
    assert kids[0].evidence.get("account_count") == 0
    assert kids[0].severity == Severity.MEDIUM
    assert any(k.rule_id.endswith("-NEXT") for k in kids)


def test_escalation_eth_accounts_disclosed():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if body["method"] == "eth_accounts":
            return rpc_result(body["id"], ["0xabc"])
        return rpc_error(body["id"], -32601, "no")

    client = httpx.Client(transport=make_transport(handler))
    target = SafeTarget(
        original_url="https://rpc.example",
        sanitized_url="https://rpc.example",
        hostname="rpc.example",
        port=443,
        scheme="https",
        resolved_ips=["1.2.3.4"],
    )
    rpc = RpcClient(target, get_profile("Standard"), client=client)
    parent = Finding(
        rule_id="EVM-NS-ACCOUNTS",
        title="Exposed eth_accounts",
        category="RPC Method Exposure",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        description="present",
        score_impact=20,
    )
    kids = run_evm_escalations(rpc, {}, [parent])
    rpc.close()
    client.close()
    assert any(k.severity == Severity.CRITICAL and "disclosed" in k.title for k in kids)
    assert any(k.rule_id.endswith("-NEXT") for k in kids)


def test_escalation_sendtransaction_deepen():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "eth_accounts":
            return rpc_result(req_id, [])
        if method == "eth_sendTransaction":
            return rpc_error(req_id, -32602, "Invalid params")
        return rpc_error(req_id, -32601, "the method does not exist")

    client = httpx.Client(transport=make_transport(handler))
    target = SafeTarget(
        original_url="https://rpc.example",
        sanitized_url="https://rpc.example",
        hostname="rpc.example",
        port=443,
        scheme="https",
        resolved_ips=["1.2.3.4"],
    )
    rpc = RpcClient(target, get_profile("Standard"), client=client)
    parent = Finding(
        rule_id="EVM-NS-ACCOUNTS",
        title="Exposed eth_accounts",
        category="RPC Method Exposure",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        kind=CheckKind.FINDING,
        description="present",
        score_impact=20,
    )
    kids = run_evm_escalations(rpc, {}, [parent])
    rpc.close()
    client.close()
    deepen = [k for k in kids if k.rule_id.endswith("-DEEPEN")]
    assert deepen
    assert deepen[0].evidence.get("classification") == "method_accepts_calls"


def test_quick_profile_skips_escalation():
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
        if method == "eth_accounts":
            return rpc_result(req_id, [])
        if method == "admin_nodeInfo":
            return rpc_result(req_id, {"name": "node"})
        return rpc_error(req_id, -32601, "the method does not exist")

    client = httpx.Client(transport=make_transport(handler))
    quick = ScannerEngine(
        "https://rpc.example",
        "Quick",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    assert not any(f.parent_rule_id for f in quick.findings)

    standard = ScannerEngine(
        "https://rpc.example",
        "Standard",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()
    assert any(f.parent_rule_id for f in standard.findings)
    assert standard.profile == ScanProfile.STANDARD
