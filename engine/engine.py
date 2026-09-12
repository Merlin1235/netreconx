from __future__ import annotations

import logging

from engine.analysis import Finding, analyze_service
from engine.assessment import Assessment
from engine.scanner import ScanManager
from engine.services import ServiceDetector


logger = logging.getLogger(__name__)


class AssessmentEngine:
    """Coordinate the complete NetReconX assessment pipeline."""

    def __init__(
        self,
        target: str,
        start_port: int,
        end_port: int,
        workers: int = 10,
        timeout: float = 0.5,
    ) -> None:
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.workers = workers
        self.timeout = timeout

    def run(self) -> Assessment:
        """Execute a complete authorized security assessment."""

        from datetime import datetime, timezone

        assessment = Assessment(
            target=self.target,
            started_at=datetime.now(timezone.utc),
        )

        logger.info(
            "Starting NetReconX assessment against %s",
            self.target,
        )

        scanner = ScanManager(
            target=self.target,
            start_port=self.start_port,
            end_port=self.end_port,
            workers=self.workers,
            timeout=self.timeout,
        )

        scan_results = scanner.run()
        assessment.scan_results = scan_results

        open_ports = assessment.open_ports

        logger.info(
            "Discovery complete: %d open ports found",
            len(open_ports),
        )

        detector = ServiceDetector(
            target=self.target,
            timeout=max(self.timeout, 1.0),
        )

        findings: list[Finding] = []

        for result in open_ports:
            service_info = detector.detect(result.port)

            finding = analyze_service(
                target=self.target,
                service_info=service_info,
            )

            findings.append(finding)

        assessment.findings = findings
        assessment.complete()

        logger.info(
            "Assessment complete: %d findings generated",
            len(findings),
        )

        return assessment
