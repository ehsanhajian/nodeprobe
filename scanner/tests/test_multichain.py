from __future__ import annotations

import json
from typing import Any

import httpx

from nodeprobe.cli import main
from nodeprobe.multichain import MultichainRpcEngine
from nodeprobe.multichain.cosmos_engine import CosmosScannerEngine
from nodeprobe.multichain.solana_engine import SolanaScannerEngine
from nodeprobe.multichain.substrate_engine import SubstrateScannerEngine
from nodeprobe.multichain.sui_engine import SuiScannerEngine


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


def test_solana_sensitive_and_inventory_on_deep():
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
        if method == "getClusterNodes":
            return rpc_result(req_id, [{"pubkey": "n1"}])
        if method in {"getProgramAccounts", "getLargestAccounts", "getLatestBlockhash"}:
            # Presence: method exists but params invalid still counts as exposed
            return rpc_error(req_id, -32602, "Invalid params")
        if method in {
            "getBalance",
            "getAccountInfo",
            "getBlockHeight",
            "getTransaction",
            "sendTransaction",
            "simulateTransaction",
            "getSignatureStatuses",
            "getMultipleAccounts",
        }:
            return rpc_error(req_id, -32602, "Invalid params")
        return rpc_error(req_id, -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = SolanaScannerEngine(
        "https://api.mainnet-beta.solana.com",
        "Deep",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert result.aborted is False
    assert any(
        f.rule_id == "SOL-NS-001" and "getProgramAccounts" in f.title for f in result.findings
    )
    assert any(f.rule_id == "SOL-DISC-003" for f in result.expected_surface)


def test_cosmos_unsafe_profiler_and_disclosure():
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
        if method == "net_info":
            return rpc_result(req_id, {"peers": [{"node_info": {"id": "p1"}}]})
        if method in {"unsafe_start_cpu_profiler", "dump_consensus_state", "dial_seeds"}:
            return rpc_error(req_id, -32602, "invalid params")
        return rpc_error(req_id, -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = CosmosScannerEngine(
        "https://rpc.cosmos.example",
        "Standard",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert result.aborted is False
    titles = {f.title for f in result.findings}
    assert any("unsafe_start_cpu_profiler" in t for t in titles)
    assert any("dump_consensus_state" in t for t in titles)

def test_cli_multichain_rules(capsys):
    assert main(["rules", "--module", "solana"]) == 0
    out = capsys.readouterr().out
    assert "SOL-IDENT-001" in out
    assert "SOL-DISC-003" in out
    assert main(["rules", "--module", "substrate"]) == 0
    assert "SUB-IDENT-001" in capsys.readouterr().out
    assert main(["rules", "--module", "cosmos"]) == 0
    cosmos_out = capsys.readouterr().out
    assert "COS-IDENT-001" in cosmos_out
    assert "COS-DISC-002" in cosmos_out
    assert main(["rules", "--module", "aptos"]) == 0
    assert "APT-IDENT-001" in capsys.readouterr().out
    assert main(["rules", "--module", "sui"]) == 0
    assert "SUI-IDENT-001" in capsys.readouterr().out


def test_aptos_scan_and_detect():
    from nodeprobe.multichain.aptos_engine import AptosScannerEngine

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.rstrip("/")
        if path.endswith("/v1") and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "chain_id": 1,
                    "epoch": "1",
                    "ledger_version": "100",
                    "oldest_ledger_version": "0",
                    "ledger_timestamp": "1",
                    "node_role": "full_node",
                    "oldest_block_height": "0",
                    "block_height": "10",
                    "git_hash": "abc123",
                },
            )
        if path.endswith("/v1/-/healthy"):
            return httpx.Response(200, json={"message": "keep going"})
        if path.endswith("/v1/info"):
            return httpx.Response(200, json={"build": "test"})
        if path.endswith("/v1/spec"):
            return httpx.Response(200, text="<html>openapi</html>")
        if path.endswith("/v1/transactions/simulate") and request.method == "POST":
            return httpx.Response(400, json={"error_code": "invalid_input"})
        if path.endswith("/v1/transactions") and request.method == "POST":
            return httpx.Response(400, json={"error_code": "invalid_input"})
        return httpx.Response(404, json={"error": "not found"})

    client = httpx.Client(transport=make_transport(handler))
    result = AptosScannerEngine(
        "https://fullnode.mainnet.aptoslabs.com/v1",
        "Standard",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    assert result.aborted is False
    assert result.chain_id == 1
    assert any(f.rule_id == "APT-DISC-001" for f in result.findings)
    assert any(f.rule_id == "APT-NS-001" for f in result.findings)

    detected = MultichainRpcEngine(
        "https://fullnode.mainnet.aptoslabs.com/v1",
        "Quick",
        family="auto",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()
    assert detected.aborted is False
    assert detected.network_name and "Aptos" in detected.network_name


def test_sui_graphql_scan_and_detect():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            # Aptos auto-detection runs before Sui detection.
            return httpx.Response(405, json={"error": "method not allowed"})

        body = json.loads(request.content.decode())
        query = body.get("query", "")
        if "NodeprobeDetect" in query:
            return httpx.Response(
                200,
                json={"data": {"chainIdentifier": "4btiuiMPvEENsttpZC7CZzC6fZR"}},
            )
        if "NodeprobeIdentity" in query:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "chainIdentifier": "4btiuiMPvEENsttpZC7CZzC6fZR",
                        "checkpoint": {
                            "sequenceNumber": 123,
                            "digest": "checkpoint-digest",
                            "timestamp": "2099-01-01T00:00:00Z",
                        },
                    }
                },
            )
        if "NodeprobeSchema" in query:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {
                                "name": "Mutation",
                                "fields": [{"name": "executeTransactionBlock"}],
                            },
                        }
                    }
                },
            )
        return rpc_error(body.get("id", 1), -32601, "Method not found")

    client = httpx.Client(transport=make_transport(handler))
    result = SuiScannerEngine(
        "https://graphql.mainnet.sui.io/graphql",
        "Standard",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()

    assert result.aborted is False
    assert result.network_name == "Sui"
    assert any(f.rule_id == "SUI-GQL-001" for f in result.findings)
    assert any(f.rule_id == "SUI-IDENT-001" for f in result.expected_surface)
    assert any(f.rule_id == "SUI-GQL-002" for f in result.expected_surface)

    deep = SuiScannerEngine(
        "https://graphql.mainnet.sui.io/graphql",
        "Deep",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    assert deep.aborted is False
    assert not any(f.rule_id == "SUI-LEGACY-001" for f in deep.findings)

    detected = MultichainRpcEngine(
        "https://graphql.mainnet.sui.io/graphql",
        "Quick",
        family="auto",
        http_client=client,
        skip_tls_probe=True,
        resolve_dns=False,
    ).run()
    client.close()

    assert detected.aborted is False
    assert detected.network_name == "Sui"
