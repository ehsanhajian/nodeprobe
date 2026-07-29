from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dapptility_scanner.models import CheckKind, Confidence, Finding, ScanProfile, Severity

if TYPE_CHECKING:
    from dapptility_scanner.rpc import RpcClient


@dataclass
class RuleMeta:
    rule_id: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    kind: CheckKind
    version: str = "0.1.0"
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    allowed_profiles: tuple[ScanProfile, ...] = (
        ScanProfile.FREE,
        ScanProfile.OUTBOUND,
        ScanProfile.AUTHORIZED_FULL,
    )
    enabled: bool = True
    score_impact: int = 0


class Rule(ABC):
    meta: RuleMeta

    def allowed_for(self, profile: ScanProfile) -> bool:
        return self.meta.enabled and profile in self.meta.allowed_profiles

    @abstractmethod
    def run(self, client: RpcClient, context: dict) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        *,
        evidence: dict | None = None,
        title: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        kind: CheckKind | None = None,
        description: str | None = None,
        score_impact: int | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.meta.rule_id,
            title=title or self.meta.title,
            category=self.meta.category,
            severity=severity or self.meta.severity,
            confidence=confidence or self.meta.confidence,
            kind=kind or self.meta.kind,
            description=description or self.meta.description,
            evidence=evidence or {},
            impact=self.meta.impact,
            remediation=self.meta.remediation,
            references=list(self.meta.references),
            score_impact=self.meta.score_impact if score_impact is None else score_impact,
        )
