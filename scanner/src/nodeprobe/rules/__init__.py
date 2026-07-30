from __future__ import annotations

from nodeprobe.rules.base import Rule
from nodeprobe.rules.client import (
    ClientVersionRule,
    ContentTypeRule,
    RpcModulesRule,
    ServerHeaderRule,
)
from nodeprobe.rules.identity import BlockNumberRule, ChainIdRule, NetVersionRule
from nodeprobe.rules.namespaces import (
    ExpectedSurfaceRule,
    ProviderInformationalRule,
    SoftRateLimitRule,
    namespace_rules,
)
from nodeprobe.rules.tls_http import CorsCredentialsRule, TlsCertificateRule


def all_rules() -> list[Rule]:
    rules: list[Rule] = [
        ChainIdRule(),
        NetVersionRule(),
        BlockNumberRule(),
        ClientVersionRule(),
        ServerHeaderRule(),
        RpcModulesRule(),
        ContentTypeRule(),
        TlsCertificateRule(),
        CorsCredentialsRule(),
        ProviderInformationalRule(),
        ExpectedSurfaceRule(),
        SoftRateLimitRule(),
    ]
    rules.extend(namespace_rules())
    return rules
