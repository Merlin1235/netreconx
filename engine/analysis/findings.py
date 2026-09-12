from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .risk import RiskLevel, risk_name


@dataclass(frozen=True)
class Finding:
    """Security observation produced by the analysis engine."""

    target: str
    port: int
    service: str
    title: str
    description: str
    risk: RiskLevel
    evidence: Optional[str] = None

    @property
    def risk_name(self) -> str:
        """Return the textual risk level."""

        return risk_name(self.risk)
