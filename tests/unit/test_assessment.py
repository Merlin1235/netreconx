from datetime import datetime, timezone

from engine.assessment import Assessment
from engine.analysis import Finding, RiskLevel
from engine.scanner import ScanResult


def test_open_ports_are_filtered() -> None:
    assessment = Assessment(
        target="127.0.0.1",
        started_at=datetime.now(timezone.utc),
        scan_results=[
            ScanResult(
                target="127.0.0.1",
                port=22,
                state="open",
            ),
            ScanResult(
                target="127.0.0.1",
                port=23,
                state="closed",
            ),
        ],
    )

    assert len(assessment.open_ports) == 1
    assert assessment.open_ports[0].port == 22


def test_high_risk_findings_are_filtered() -> None:
    assessment = Assessment(
        target="127.0.0.1",
        started_at=datetime.now(timezone.utc),
        findings=[
            Finding(
                target="127.0.0.1",
                port=23,
                service="telnet",
                title="Exposed Telnet Service",
                description="Test finding",
                risk=RiskLevel.HIGH,
            ),
            Finding(
                target="127.0.0.1",
                port=80,
                service="http",
                title="Exposed HTTP Service",
                description="Test finding",
                risk=RiskLevel.LOW,
            ),
        ],
    )

    assert len(assessment.high_risk_findings) == 1
    assert assessment.high_risk_findings[0].port == 23


def test_assessment_can_be_completed() -> None:
    assessment = Assessment(
        target="127.0.0.1",
        started_at=datetime.now(timezone.utc),
    )

    assert assessment.completed_at is None

    assessment.complete()

    assert assessment.completed_at is not None
