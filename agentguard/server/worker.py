"""Background jobs: approval expiry, stuck-execution detection, notification delivery.

Runs in-process by default (AGENTGUARD_WORKER_ENABLED=true). Every job is safe
to run on several replicas at once: state changes are conditional and happen
under the org lock, and deliveries are claimed with SKIP LOCKED on Postgres.
Run `agentguard worker` to host it in a separate process instead.
"""
from __future__ import annotations

import logging
import threading

from agentguard.server.metrics import Metrics
from agentguard.server.notifications import Notifier
from agentguard.server.service import Gateway

log = logging.getLogger("agentguard.worker")


class Worker:
    def __init__(self, gateway: Gateway, notifier: Notifier, metrics: Metrics, interval: float = 5.0):
        self.gateway = gateway
        self.notifier = notifier
        self.metrics = metrics
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> dict:
        out = {"expired": self.gateway.expire_all(), "stuck": self.gateway.mark_stuck(), "delivered": self.notifier.deliver_due()}
        self.metrics.pending_approvals.set(self.gateway.count_pending())
        return out

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                result = self.run_once()
                self.metrics.worker_runs.labels("ok").inc()
                if any(result.values()):
                    log.info("worker run", extra={"result": result})
            except Exception:  # keep running; one bad row must not stop expiry or delivery
                self.metrics.worker_runs.labels("error").inc()
                log.exception("worker iteration failed")
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="agentguard-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
