from __future__ import annotations

import json
from typing import Any

import httpx

from nodeprobe.cli import main
from nodeprobe.multichain import MultichainRpcEngine
from nodeprobe.multichain.cosmos_engine import CosmosScannerEngine
from nodeprobe.multichain.solana_engine import SolanaScannerEngine
from nodeprobe.multichain.substrate_engine import SubstrateScannerEngine


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


def test_solana_scan_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "getHealth":
            return rpc_result(req_id, "ok")
        if method == "getVersion":
            return rpc_result(req_id, {"solana-core": "1.18.0"})
        if method == "getSlot":
            return rpc_result(req_id, 123)
        if method == "getEpochInfo":
            return rpc_result(req_id, {"epoch": 1})
        if method == "getIdentity":
            return rpc_result(req_id, {"identity": "Abc123"})
        return rpc_error(req_id, -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = SolanaScannerEngine(
        "https://api.mainnet-beta.solana.com",
        "Quick",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert result.aborted is False
    assert result.network_name == "Solana"
    assert result.client_version == "1.18.0"
    assert any(f.rule_id == "SOL-DISC-001" for f in result.findings)


def test_substrate_scan_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "system_chain":
            return rpc_result(req_id, "Polkadot")
        if method == "system_name":
            return rpc_result(req_id, "Parity Polkadot")
        if method == "system_version":
            return rpc_result(req_id, "1.0.0")
        if method == "system_health":
            return rpc_result(req_id, {"peers": 25, "isSyncing": False, "shouldHavePeers": True})
        if method == "rpc_methods":
            return rpc_result(req_id, {"methods": ["system_chain", "author_rotateKeys"]})
        return rpc_error(req_id, -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = SubstrateScannerEngine(
        "https://rpc.polkadot.io",
        "Standard",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert result.aborted is False
    assert result.network_name == "Polkadot"
    assert any(f.rule_id == "SUB-DISC-001" for f in result.findings)


def test_cosmos_scan_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "status":
            return rpc_result(
                req_id,
                {
                    "node_info": {
                        "network": "cosmoshub-4",
                        "version": "0.37.0",
                        "moniker": "hub",
                    },
                    "sync_info": {"catching_up": False},
                },
            )
        return rpc_error(req_id, -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = CosmosScannerEngine(
        "https://rpc.cosmos.example",
        "Quick",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert result.aborted is False
    assert result.network_name == "cosmoshub-4"


def test_auto_detect_solana():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        method = body["method"]
        req_id = body["id"]
        if method == "getHealth":
            return rpc_result(req_id, "ok")
        if method == "getVersion":
            return rpc_result(req_id, {"solana-core": "1.18.0"})
        if method in {"getSlot", "getEpochInfo"}:
            return rpc_result(req_id, 1 if method == "getSlot" else {"epoch": 1})
        return rpc_error(req_id, -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = MultichainRpcEngine(
        "https://api.mainnet-beta.solana.com",
        "Quick",
        family="auto",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()
    assert result.aborted is False
    assert result.network_name == "Solana"


def test_cli_multichain_rules(capsys):
    assert main(["rules", "--module", "solana"]) == 0
    out = capsys.readouterr().out
    assert "SOL-IDENT-001" in out
    assert main(["rules", "--module", "substrate"]) == 0
    assert "SUB-IDENT-001" in capsys.readouterr().out
    assert main(["rules", "--module", "cosmos"]) == 0
    assert "COS-IDENT-001" in capsys.readouterr().out
