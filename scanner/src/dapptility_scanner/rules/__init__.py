from __future__ import annotations

from dapptility_scanner.rules.base import Rule
from dapptility_scanner.rules.client import (
    ClientVersionRule,
    ContentTypeRule,
    RpcModulesRule,
    ServerHeaderRule,
)
from dapptility_scanner.rules.identity import BlockNumberRule, ChainIdRule, NetVersionRule
from dapptility_scanner.rules.namespaces import (
    ExpectedSurfaceRule,
    ProviderInformationalRule,
    SoftRateLimitRule,
    namespace_rules,
)
from dapptility_scanner.rules.tls_http import CorsCredentialsRule, TlsCertificateRule


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
