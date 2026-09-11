from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ScanResult:
    """Result produced by a TCP port check."""

    target: str
    port: int
    state: str
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class TCPScanner:
    """Perform controlled TCP connection checks against an authorized target."""

    def __init__(self, target: str, timeout: float = 0.5) -> None:
        if not target:
            raise ValueError("Target must not be empty.")

        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        self.target = target
        self.timeout = timeout

    def scan_port(self, port: int) -> ScanResult:
        """Check whether a TCP port accepts a connection."""

        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port}")

        start = time.perf_counter()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)

                result = sock.connect_ex((self.target, port))

            latency_ms = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            if result == 0:
                return ScanResult(
                    target=self.target,
                    port=port,
                    state="open",
                    latency_ms=latency_ms,
                )

            return ScanResult(
                target=self.target,
                port=port,
                state="closed",
                latency_ms=latency_ms,
            )

        except socket.timeout:
            return ScanResult(
                target=self.target,
                port=port,
                state="timeout",
            )

        except OSError as exc:
            return ScanResult(
                target=self.target,
                port=port,
                state="error",
                error=str(exc),
            )
