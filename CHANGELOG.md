# Changelog

## 0.2.0

From prototype to product.

- **Multi-tenancy**: organizations with isolated agents, policies, secrets, actions and audit chains.
- **Identity**: user accounts, roles (owner, admin, approver, viewer), sessions, invitations, scoped API tokens, login throttling.
- **Versioned policies**: validate, diff, activate, roll back; strict schema (unknown keys are errors); requests execute under the version that decided them.
- **Encrypted secret store**: write-only per-org connector credentials; action params encrypted at rest; key rotation.
- **Approvals**: per-rule approver roles and minimum approvers (two-person rule); one vote per person; tokens can't approve; Slack Approve/Deny buttons.
- **Notifications**: transactional outbox, HMAC-signed webhooks, Slack, retries with backoff.
- **Worker**: approval expiry, stuck-execution detection (`unknown` outcome), delivery.
- **Connectors**: Stripe (exact minor-unit conversion), generic HTTP; SSRF guard on all outbound calls.
- **MCP server** (`agentguard mcp`).
- **Operations**: Postgres support with per-org row locking, Alembic migrations, health/readiness, Prometheus metrics, JSON logs, security headers and CSP, Docker image, docker-compose, CI.
- **Dashboard** rebuilt: overview, approvals, actions with timelines, agents, policy editor and simulator, secrets, integrations, team, audit.

## 0.1.0

Single-tenant prototype: policy engine, approvals, audit chain, SDK, dashboard.
