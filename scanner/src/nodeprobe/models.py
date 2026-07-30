from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    NEEDS_REVIEW = "Needs Review"


class CheckKind(str, Enum):
    EXPECTED_SURFACE = "expected_surface"
    FINDING = "finding"
    INFO = "info"


class ScanProfile(str, Enum):
    QUICK = "Quick"
    STANDARD = "Standard"
    DEEP = "Deep"


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    kind: CheckKind
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    score_impact: int = 0
    parent_rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["kind"] = self.kind.value
        return data


@dataclass
class ScanError:
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scanner_version: str
    profile: ScanProfile
    endpoint: str
    started_at: str
    finished_at: str
    duration_ms: int
    requests_made: int
    chain_id: int | None
    network_name: str | None
    client_version: str | None
    score: int
    findings: list[Finding]
    expected_surface: list[Finding]
    errors: list[ScanError]
    aborted: bool = False
    abort_reason: str | None = None
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_version": self.scanner_version,
            "profile": self.profile.value,
            "endpoint": self.endpoint,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "requests_made": self.requests_made,
            "chain_id": self.chain_id,
            "network_name": self.network_name,
            "client_version": self.client_version,
            "provider": self.provider,
            "score": self.score,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "findings": [f.to_dict() for f in self.findings],
            "expected_surface": [f.to_dict() for f in self.expected_surface],
            "errors": [e.to_dict() for e in self.errors],
            "summary": {
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
                "expected_surface": len(self.expected_surface),
            },
        }
