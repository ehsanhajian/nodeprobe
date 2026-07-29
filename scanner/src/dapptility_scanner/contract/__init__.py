from dapptility_scanner.contract.address import is_empty_code, normalize_address
from dapptility_scanner.contract.bytecode import analyze_bytecode, extract_selectors
from dapptility_scanner.contract.interfaces import interfaces_from_abi, interfaces_from_selectors
from dapptility_scanner.contract.proxy import detect_eip1167, detect_proxies_from_slots
from dapptility_scanner.contract.sourcify import SourcifyMatch, fetch_sourcify

__all__ = [
    "SourcifyMatch",
    "analyze_bytecode",
    "detect_eip1167",
    "detect_proxies_from_slots",
    "extract_selectors",
    "fetch_sourcify",
    "interfaces_from_abi",
    "interfaces_from_selectors",
    "is_empty_code",
    "normalize_address",
]
