"""Prometheus metrics. One registry per app instance (keeps tests isolated)."""
from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest


class Metrics:
    content_type = CONTENT_TYPE_LATEST

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.actions = Counter("agentguard_actions_total", "Action requests by policy decision", ["decision"], registry=self.registry)
        self.executions = Counter("agentguard_executions_total", "Connector executions by outcome", ["outcome"], registry=self.registry)
        self.execution_seconds = Histogram(
            "agentguard_execution_seconds", "Connector execution latency", registry=self.registry,
            buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
        )
        self.approvals = Counter("agentguard_approval_votes_total", "Approval votes", ["decision", "via"], registry=self.registry)
        self.deliveries = Counter("agentguard_notification_deliveries_total", "Notification attempts", ["kind", "outcome"], registry=self.registry)
        self.worker_runs = Counter("agentguard_worker_runs_total", "Background worker iterations", ["outcome"], registry=self.registry)
        self.pending_approvals = Gauge("agentguard_pending_approvals", "Actions waiting for approval (all orgs)", registry=self.registry)

    def render(self) -> bytes:
        return generate_latest(self.registry)
