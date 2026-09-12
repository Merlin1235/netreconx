from engine.analysis.risk import (
    RiskLevel,
    calculate_exposure_risk,
    risk_name,
)


def test_telnet_is_high_risk() -> None:
    result = calculate_exposure_risk("telnet", 23)

    assert result == RiskLevel.HIGH


def test_ftp_is_medium_risk() -> None:
    result = calculate_exposure_risk("ftp", 21)

    assert result == RiskLevel.MEDIUM


def test_ssh_is_low_exposure_risk() -> None:
    result = calculate_exposure_risk("ssh", 22)

    assert result == RiskLevel.LOW


def test_unknown_service_is_informational() -> None:
    result = calculate_exposure_risk("unknown", 50000)

    assert result == RiskLevel.INFORMATIONAL


def test_risk_name() -> None:
    assert risk_name(RiskLevel.HIGH) == "high"
