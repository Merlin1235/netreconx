from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from engine.analysis import Finding
from engine.scanner import ScanResult


@dataclass
class Assessment:
    """Complete result of a NetReconX security assessment."""

    target: str
    started_at: datetime
    completed_at: datetime | None = None

    scan_results: list[ScanResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def open_ports(self) -> list[ScanResult]:
        """Return only ports that accepted a TCP connection."""

        return [
            result
            for result in self.scan_results
            if result.state == "open"
        ]

    @property
    def high_risk_findings(self) -> list[Finding]:
        """Return high-risk findings."""

        return [
            finding
            for finding in self.findings
            if finding.risk_name == "high"
        ]

    def complete(self) -> None:
        """Mark the assessment as completed."""

        self.completed_at = datetime.now(timezone.utc)
