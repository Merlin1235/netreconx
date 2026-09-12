from engine.analysis.findings import analyze_service
from engine.analysis.risk import RiskLevel
from engine.services.detector import ServiceInfo


def test_telnet_creates_high_risk_finding() -> None:
    service = ServiceInfo(
        port=23,
        service="telnet",
    )

    finding = analyze_service(
        target="127.0.0.1",
        service_info=service,
    )

    assert finding.port == 23
    assert finding.service == "telnet"
    assert finding.risk == RiskLevel.HIGH
    assert "Telnet" in finding.title


def test_http_creates_low_risk_exposure_finding() -> None:
    service = ServiceInfo(
        port=80,
        service="http",
    )

    finding = analyze_service(
        target="127.0.0.1",
        service_info=service,
    )

    assert finding.risk == RiskLevel.LOW
    assert finding.port == 80
