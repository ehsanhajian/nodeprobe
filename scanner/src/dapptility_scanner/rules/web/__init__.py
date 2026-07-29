from __future__ import annotations

from dapptility_scanner.rules.base import Rule
from dapptility_scanner.rules.web.headers import SecurityHeadersRule, ServerDisclosureRule
from dapptility_scanner.rules.web.tls import WebTlsRule
from dapptility_scanner.rules.web.well_known import RobotsTxtRule, SecurityTxtRule


def web_rules() -> list[Rule]:
    return [
        WebTlsRule(),
        SecurityHeadersRule(),
        ServerDisclosureRule(),
        SecurityTxtRule(),
        RobotsTxtRule(),
    ]
