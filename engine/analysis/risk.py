from __future__ import annotations

from enum import IntEnum


class RiskLevel(IntEnum):
    """Severity levels used by the NetReconX assessment engine."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


def risk_name(level: RiskLevel) -> str:
    """Return a human-readable risk level."""

    return level.name.lower()


def calculate_exposure_risk(
    service: str,
    port: int,
) -> RiskLevel:
    """
    Calculate an initial educational exposure risk.

    This function evaluates service exposure only.
    It does NOT determine whether a vulnerability exists.
    """

    sensitive_services = {
        "telnet": RiskLevel.HIGH,
        "ftp": RiskLevel.MEDIUM,
        "redis": RiskLevel.HIGH,
        "mysql": RiskLevel.MEDIUM,
        "postgresql": RiskLevel.MEDIUM,
    }

    if service in sensitive_services:
        return sensitive_services[service]

    if port in {22, 80, 443, 8080}:
        return RiskLevel.LOW

    return RiskLevel.INFORMATIONAL
