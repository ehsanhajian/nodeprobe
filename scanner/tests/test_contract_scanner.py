from __future__ import annotations

import httpx
import pytest

from dapptility_scanner import killswitch
from dapptility_scanner.cli import main
from dapptility_scanner.contract.bytecode import analyze_bytecode, extract_selectors
from dapptility_scanner.contract.proxy import detect_eip1167, detect_proxies_from_slots
from dapptility_scanner.contract_engine import ContractScannerEngine
from dapptility_scanner.models import ScanProfile, ScanResult


@pytest.fixture(autouse=True)
def _reset_killswitch():
    killswitch.reset()
    yield
    killswitch.reset()


# Minimal EIP-1167-style runtime: prefix + 20-byte impl + suffix
EIP1167_CODE = (
    "0x"
    + "363d3d373d3d3d363d73"
    + "1111111111111111111111111111111111111111"
    + "5af43d82803e903d91602b57fd5bf3"
)

# Bytecode with PUSH4 selector for owner() and a DELEGATECALL + SELFDESTRUCT
HEURISTIC_CODE = (
    "0x"
    + "63"  # PUSH4
    + "8da5cb5b"  # owner()
    + "14"  # EQ (padding noise)
    + "f4"  # DELEGATECALL
    + "ff"  # SELFDESTRUCT
)


def test_eip1167_and_opcodes():
    hint = detect_eip1167(EIP1167_CODE)
    assert hint is not None
    assert hint.implementation == "0x1111111111111111111111111111111111111111"
    hits = {h.name: h.count for h in analyze_bytecode(HEURISTIC_CODE)}
    assert hits["DELEGATECALL"] >= 1
    assert hits["SELFDESTRUCT"] >= 1
    assert "0x8da5cb5b" in extract_selectors(HEURISTIC_CODE)


def test_storage_proxy_slots():
    slots = {
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": (
            "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": (
            "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ),
    }

    def get_storage(slot: str):
        return slots.get(slot)

    hints = detect_proxies_from_slots(get_storage=get_storage)
    assert any(h.kind == "eip1967" for h in hints)
    eip = next(h for h in hints if h.kind == "eip1967")
    assert eip.implementation == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert eip.admin == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_contract_engine_proxy(monkeypatch):
    address = "0x2222222222222222222222222222222222222222"
    impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read()
        import json

        body = json.loads(payload)
        method = body.get("method")
        req_id = body.get("id", 1)
        if method == "eth_chainId":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x1"})
        if method == "eth_getCode":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": req_id, "result": EIP1167_CODE},
            )
        if method == "eth_getStorageAt":
            params = body.get("params") or []
            slot = params[1] if len(params) > 1 else ""
            if slot == impl_slot:
                result = "0x0000000000000000000000001111111111111111111111111111111111111111"
            else:
                result = "0x" + ("00" * 32)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": result})
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "missing"}},
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
        profile="Free",
        http_client=client,
        resolve_dns=False,
        fetch_verification=True,
    ).run()

    assert not result.aborted
    assert result.chain_id == 1
    rule_ids = {f.rule_id for f in result.findings + result.expected_surface}
    assert "SC-PROXY-001" in rule_ids
    assert "SC-CODE-001" in rule_ids
    assert any("eip1167" in f.title.lower() or (f.evidence or {}).get("kind") == "eip1167" for f in result.findings)


def test_cli_contract_rules(capsys, monkeypatch):
    class FakeEngine:
        def __init__(self, *a, **k):
            pass

        def run(self):
            return ScanResult(
                scanner_version="0.1.0",
                profile=ScanProfile.QUICK,
                endpoint="0xabc@https://rpc.example",
                started_at="t0",
                finished_at="t1",
                duration_ms=1,
                requests_made=2,
                chain_id=1,
                network_name="Ethereum Mainnet",
                client_version=None,
                score=88,
                findings=[],
                expected_surface=[],
                errors=[],
            )

    monkeypatch.setattr("dapptility_scanner.cli.ContractScannerEngine", FakeEngine)
    assert (
        main(
            [
                "contract",
                "0x1111111111111111111111111111111111111111",
                "--rpc",
                "https://rpc.example",
                "--chain",
                "1",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "Dapptility scan report" in out
    assert "Ethereum Mainnet" in out

    assert main(["rules", "--module", "contract"]) == 0
    assert "SC-PROXY-001" in capsys.readouterr().out
