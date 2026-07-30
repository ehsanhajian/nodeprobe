from __future__ import annotations

from nodeprobe.rules.base import Rule
from nodeprobe.rules.web.headers import SecurityHeadersRule, ServerDisclosureRule
from nodeprobe.rules.web.tls import WebTlsRule
from nodeprobe.rules.web.well_known import RobotsTxtRule, SecurityTxtRule


def web_rules() -> list[Rule]:
    return [
        WebTlsRule(),
        SecurityHeadersRule(),
        ServerDisclosureRule(),
        SecurityTxtRule(),
        RobotsTxtRule(),
    ]
