from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from engine.services.detector import ServiceInfo

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


def analyze_service(
    target: str,
    service_info: ServiceInfo,
) -> Finding:
    """Convert service discovery information into a security finding."""

    service = service_info.service
    port = service_info.port

    risk = RiskLevel.INFORMATIONAL
    title = f"Exposed {service} service"

    description = (
        f"The {service} service is reachable on TCP port {port}. "
        "Review whether this service is required and appropriately protected."
    )

    if service == "telnet":
        risk = RiskLevel.HIGH
        title = "Exposed Telnet Service"
        description = (
            "Telnet provides remote access and should generally be replaced "
            "with a securely configured alternative such as SSH."
        )

    elif service == "ftp":
        risk = RiskLevel.MEDIUM
        title = "Exposed FTP Service"
        description = (
            "An FTP service is reachable. Review whether unencrypted "
            "file-transfer functionality is required."
        )

    elif service in {"mysql", "postgresql", "redis"}:
        risk = RiskLevel.MEDIUM
        title = f"Exposed {service} Service"
        description = (
            f"The {service} service appears reachable over TCP. "
            "Database and data services should normally be restricted "
            "to authorized hosts and networks."
        )

    elif service in {"ssh", "http", "https", "http-alt"}:
        risk = calculate_exposure_risk(
            service=service,
            port=port,
        )

    return Finding(
        target=target,
        port=port,
        service=service,
        title=title,
        description=description,
        risk=risk,
        evidence=service_info.banner,
    )
