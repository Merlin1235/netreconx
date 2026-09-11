from __future__ import annotations

import logging
import threading
from queue import Queue
from typing import Callable, Optional

from .tcp import ScanResult, TCPScanner


logger = logging.getLogger(__name__)


class ScanWorker:
    """Worker that consumes port-scan jobs from a queue."""

    def __init__(
        self,
        job_queue: Queue[Optional[int]],
        scanner: TCPScanner,
        result_callback: Callable[[ScanResult], None],
    ) -> None:
        self.job_queue = job_queue
        self.scanner = scanner
        self.result_callback = result_callback

    def run(self) -> None:
        """Process jobs until a shutdown signal is received."""

        thread_name = threading.current_thread().name
        logger.debug("Worker %s started", thread_name)

        while True:
            port = self.job_queue.get()

            try:
                if port is None:
                    logger.debug("Worker %s stopping", thread_name)
                    return

                result = self.scanner.scan_port(port)
                self.result_callback(result)

            except Exception:
                logger.exception(
                    "Worker %s failed while processing port %s",
                    thread_name,
                    port,
                )

            finally:
                self.job_queue.task_done()
