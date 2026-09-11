from __future__ import annotations

import logging
import threading
from queue import Queue
from typing import Optional

from .tcp import ScanResult, TCPScanner
from .worker import ScanWorker


logger = logging.getLogger(__name__)


class ScanManager:
    """Coordinate a multithreaded TCP scanning operation."""

    def __init__(
        self,
        target: str,
        start_port: int,
        end_port: int,
        workers: int = 10,
        timeout: float = 0.5,
    ) -> None:

        if not 1 <= start_port <= 65535:
            raise ValueError("Invalid start port.")

        if not 1 <= end_port <= 65535:
            raise ValueError("Invalid end port.")

        if start_port > end_port:
            raise ValueError("Start port cannot exceed end port.")

        if workers < 1:
            raise ValueError("Worker count must be at least 1.")

        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.worker_count = workers
        self.timeout = timeout

        self.job_queue: Queue[Optional[int]] = Queue()
        self.results: list[ScanResult] = []

        self._results_lock = threading.Lock()

    def _store_result(self, result: ScanResult) -> None:
        """Store a result safely from multiple worker threads."""

        with self._results_lock:
            self.results.append(result)

    def run(self) -> list[ScanResult]:
        """Execute the scan and return results ordered by port."""

        logger.info(
            "Starting scan: target=%s ports=%s-%s workers=%s",
            self.target,
            self.start_port,
            self.end_port,
            self.worker_count,
        )

        scanner = TCPScanner(
            target=self.target,
            timeout=self.timeout,
        )

        threads: list[threading.Thread] = []

        for index in range(self.worker_count):
            worker = ScanWorker(
                job_queue=self.job_queue,
                scanner=scanner,
                result_callback=self._store_result,
            )

            thread = threading.Thread(
                target=worker.run,
                name=f"scanner-worker-{index + 1}",
                daemon=True,
            )

            thread.start()
            threads.append(thread)

        for port in range(self.start_port, self.end_port + 1):
            self.job_queue.put(port)

        self.job_queue.join()

        for _ in threads:
            self.job_queue.put(None)

        for thread in threads:
            thread.join()

        ordered_results = sorted(
            self.results,
            key=lambda result: result.port,
        )

        logger.info(
            "Scan completed: %s ports processed",
            len(ordered_results),
        )

        return ordered_results
