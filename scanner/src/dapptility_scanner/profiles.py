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
    ScanProfile.QUICK: ProfileLimits(
        name=ScanProfile.QUICK,
        max_requests=40,
        max_rps=2.0,
        max_duration_seconds=60.0,
        allow_expensive_namespace_calls=False,
        allow_rate_limit_stress=False,
    ),
    ScanProfile.STANDARD: ProfileLimits(
        name=ScanProfile.STANDARD,
        max_requests=80,
        max_rps=3.0,
        max_duration_seconds=120.0,
        allow_expensive_namespace_calls=False,
        allow_rate_limit_stress=False,
    ),
    ScanProfile.DEEP: ProfileLimits(
        name=ScanProfile.DEEP,
        max_requests=200,
        max_rps=5.0,
        max_duration_seconds=300.0,
        allow_expensive_namespace_calls=True,
        allow_rate_limit_stress=True,
    ),
}

# Legacy commercial-funnel names → personal profiles
_PROFILE_ALIASES: dict[str, ScanProfile] = {
    "quick": ScanProfile.QUICK,
    "standard": ScanProfile.STANDARD,
    "deep": ScanProfile.DEEP,
    # Legacy aliases (CLI / old DB rows)
    "free": ScanProfile.QUICK,
    "outbound": ScanProfile.STANDARD,
    "authorized-full": ScanProfile.DEEP,
    "authorizedfull": ScanProfile.DEEP,
    "full": ScanProfile.DEEP,
}


def normalize_profile_name(name: str) -> ScanProfile:
    normalized = name.strip().lower().replace("_", "-")
    key = _PROFILE_ALIASES.get(normalized)
    if key is None:
        valid = ", ".join(p.value for p in ScanProfile)
        raise ValueError(
            f"Unknown scan profile '{name}'. Valid: {valid} "
            "(aliases: Free→Quick, Outbound→Standard, Authorized-Full→Deep)"
        )
    return key


def get_profile(name: str) -> ProfileLimits:
    return PROFILES[normalize_profile_name(name)]
