from __future__ import annotations

from dataclasses import dataclass

from dapptility_scanner.models import ScanProfile


@dataclass(frozen=True)
class ProfileLimits:
    name: ScanProfile
    max_requests: int
    max_rps: float
    max_duration_seconds: float
    allow_expensive_namespace_calls: bool
    allow_rate_limit_stress: bool


PROFILES: dict[ScanProfile, ProfileLimits] = {
    ScanProfile.FREE: ProfileLimits(
        name=ScanProfile.FREE,
        max_requests=40,
        max_rps=2.0,
        max_duration_seconds=60.0,
        allow_expensive_namespace_calls=False,
        allow_rate_limit_stress=False,
    ),
    ScanProfile.OUTBOUND: ProfileLimits(
        name=ScanProfile.OUTBOUND,
        max_requests=40,
        max_rps=1.0,
        max_duration_seconds=60.0,
        allow_expensive_namespace_calls=False,
        allow_rate_limit_stress=False,
    ),
    ScanProfile.AUTHORIZED_FULL: ProfileLimits(
        name=ScanProfile.AUTHORIZED_FULL,
        max_requests=200,
        max_rps=5.0,
        max_duration_seconds=300.0,
        allow_expensive_namespace_calls=True,
        allow_rate_limit_stress=True,
    ),
}


def get_profile(name: str) -> ProfileLimits:
    normalized = name.strip().lower().replace("_", "-")
    mapping = {
        "free": ScanProfile.FREE,
        "outbound": ScanProfile.OUTBOUND,
        "authorized-full": ScanProfile.AUTHORIZED_FULL,
        "authorizedfull": ScanProfile.AUTHORIZED_FULL,
        "full": ScanProfile.AUTHORIZED_FULL,
    }
    key = mapping.get(normalized)
    if key is None:
        valid = ", ".join(p.value for p in ScanProfile)
        raise ValueError(f"Unknown scan profile '{name}'. Valid: {valid}")
    return PROFILES[key]
