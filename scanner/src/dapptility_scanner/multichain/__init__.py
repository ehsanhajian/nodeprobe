"""Dispatch RPC scans across EVM / Solana / Substrate / Cosmos families."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from dapptility_scanner import __version__, killswitch
from dapptility_scanner.engine import ScannerEngine
from dapptility_scanner.killswitch import KillSwitchActive
from dapptility_scanner.models import ScanError, ScanProfile, ScanResult
from dapptility_scanner.multichain.cosmos_engine import CosmosScannerEngine
from dapptility_scanner.multichain.detect import RpcFamily, detect_family
from dapptility_scanner.multichain.solana_engine import SolanaScannerEngine
from dapptility_scanner.multichain.substrate_engine import SubstrateScannerEngine
from dapptility_scanner.profiles import ProfileLimits, get_profile
from dapptility_scanner.rpc import RpcClient
from dapptility_scanner.safety import UnsafeTargetError, mask_credentials, validate_target


class MultichainRpcEngine:
    def __init__(
        self,
        url: str,
        profile: str | ScanProfile | ProfileLimits = "Quick",
        *,
        family: str = "auto",
        block_providers: bool = False,
        http_client: httpx.Client | None = None,
        skip_tls_probe: bool = False,
        resolve_dns: bool = True,
    ):
        if isinstance(profile, ProfileLimits):
            self.limits = profile
            self.profile_arg: str | ScanProfile | ProfileLimits = profile
        elif isinstance(profile, ScanProfile):
            self.limits = get_profile(profile.value)
            self.profile_arg = profile
        else:
            self.limits = get_profile(profile)
            self.profile_arg = profile
        self.url = url
        self.family = family.strip().lower()
        self.block_providers = block_providers
        self.http_client = http_client
        self.skip_tls_probe = skip_tls_probe
        self.resolve_dns = resolve_dns

    def run(self) -> ScanResult:
        family = self.family
        if family in {"auto", "detect", ""}:
            try:
                detected = self._detect()
            except KillSwitchActive as exc:
                started = datetime.now(timezone.utc)
                return ScanResult(
                    scanner_version=__version__,
                    profile=self.limits.name,
                    endpoint=mask_credentials(self.url),
                    started_at=started.isoformat(),
                    finished_at=started.isoformat(),
                    duration_ms=0,
                    requests_made=0,
                    chain_id=None,
                    network_name=None,
                    client_version=None,
                    score=0,
                    findings=[],
                    expected_surface=[],
                    errors=[ScanError(code="kill_switch", message=str(exc))],
                    aborted=True,
                    abort_reason="kill_switch",
                )
            except UnsafeTargetError as exc:
                started = datetime.now(timezone.utc)
                return ScanResult(
                    scanner_version=__version__,
                    profile=self.limits.name,
                    endpoint=mask_credentials(self.url),
                    started_at=started.isoformat(),
                    finished_at=started.isoformat(),
                    duration_ms=0,
                    requests_made=0,
                    chain_id=None,
                    network_name=None,
                    client_version=None,
                    score=0,
                    findings=[],
                    expected_surface=[],
                    errors=[ScanError(code="unsafe_target", message=str(exc))],
                    aborted=True,
                    abort_reason="unsafe_target",
                )
            if detected is None:
                started = datetime.now(timezone.utc)
                return ScanResult(
                    scanner_version=__version__,
                    profile=self.limits.name,
                    endpoint=mask_credentials(self.url),
                    started_at=started.isoformat(),
                    finished_at=started.isoformat(),
                    duration_ms=0,
                    requests_made=0,
                    chain_id=None,
                    network_name=None,
                    client_version=None,
                    score=0,
                    findings=[],
                    expected_surface=[],
                    errors=[
                        ScanError(
                            code="unknown_family",
                            message=(
                                "Could not detect RPC family. "
                                "Pass --family evm|solana|substrate|cosmos."
                            ),
                        )
                    ],
                    aborted=True,
                    abort_reason="unknown_family",
                )
            family = detected

        if family == "evm":
            return ScannerEngine(
                self.url,
                self.profile_arg,
                block_providers=self.block_providers,
                http_client=self.http_client,
                skip_tls_probe=self.skip_tls_probe,
                resolve_dns=self.resolve_dns,
            ).run()
        if family == "solana":
            return SolanaScannerEngine(
                self.url,
                self.profile_arg,
                http_client=self.http_client,
                skip_tls_probe=self.skip_tls_probe,
                resolve_dns=self.resolve_dns,
            ).run()
        if family in {"substrate", "polkadot"}:
            return SubstrateScannerEngine(
                self.url,
                self.profile_arg,
                http_client=self.http_client,
                skip_tls_probe=self.skip_tls_probe,
                resolve_dns=self.resolve_dns,
            ).run()
        if family in {"cosmos", "tendermint"}:
            return CosmosScannerEngine(
                self.url,
                self.profile_arg,
                http_client=self.http_client,
                skip_tls_probe=self.skip_tls_probe,
                resolve_dns=self.resolve_dns,
            ).run()

        started = datetime.now(timezone.utc)
        return ScanResult(
            scanner_version=__version__,
            profile=self.limits.name,
            endpoint=mask_credentials(self.url),
            started_at=started.isoformat(),
            finished_at=started.isoformat(),
            duration_ms=0,
            requests_made=0,
            chain_id=None,
            network_name=None,
            client_version=None,
            score=0,
            findings=[],
            expected_surface=[],
            errors=[
                ScanError(
                    code="unknown_family",
                    message=f"Unknown RPC family '{self.family}'.",
                )
            ],
            aborted=True,
            abort_reason="unknown_family",
        )

    def _detect(self) -> RpcFamily | None:
        try:
            killswitch.check()
            target = validate_target(self.url, resolve_dns=self.resolve_dns)
            with RpcClient(target, self.limits, client=self.http_client) as client:
                return detect_family(client)
        except (KillSwitchActive, UnsafeTargetError):
            raise
        except Exception:  # noqa: BLE001
            return None
