# AgentGuard

**The action gateway for AI agents.** Your agents never hold the keys to Stripe, your CRM or your email provider. They ask AgentGuard to act. AgentGuard checks every request against your policy, then runs it, routes it to the right people for approval, or blocks it, and writes every step to a tamper-evident audit log.

```
  AI agents ──(agent key only)──► AgentGuard ──(credentials it holds)──► Stripe · CRM · email · internal APIs
  (SDK, MCP, HTTP)                    │
                       policy-as-code: allow · review · block
                       approvals in the dashboard or Slack · two-person rule
                       rate limits + kill switch · encrypted secrets
                       hash-chained audit log · webhooks · metrics
```

Logging what an agent did is advisory; enforcement is real only when the agent **cannot** reach the downstream system except through the gateway. That is the design center of AgentGuard.

## Features

**Enforcement**
- **Credential brokering.** Connector secrets live encrypted in each organization's secret store (write-only through the API). Agents authenticate with their own key and never see downstream credentials.
- **Policy as code.** YAML rules match agents, actions and parameter conditions. The most restrictive matching rule wins, so rule order can never weaken a decision, and anything not explicitly allowed is blocked. Policies are immutable, numbered versions you can validate, diff, activate and roll back.
- **Approvals that hold up.** Each rule sets how many approvers are needed and which roles may approve (e.g. two different admins for refunds over $500). Nobody can vote twice, any denial is final, approvals expire, API tokens can never approve, and a paused agent's actions cannot be approved. Approve from the dashboard or with **Approve / Deny buttons in Slack**.
- **Kill switch.** Per-agent sliding-window rate limits can auto-pause a looping agent; operators can pause, resume, rotate keys or disable agents permanently.
- **Strict validation.** Typed param schemas (types, enums, no unknown fields, size limits), so `"amount": "10"` can never satisfy an `amount <= 50` rule.
- **Exactly-once intent.** Idempotency keys end to end, passed downstream (`Idempotency-Key`). Executions that never report back are marked `unknown` for a human to check rather than silently retried.

**Operations**
- **Multi-tenant.** Organizations with isolated data, policies, secrets and audit chains; users can belong to several.
- **Roles.** owner, admin, approver, viewer; invitations; scoped API tokens for automation; session sign-out on password change; login throttling.
- **Audit.** Every decision, vote, policy and configuration change is an event in a per-organization SHA-256 hash chain. Verification detects edits, deletions, reordering and truncation. Export as NDJSON.
- **Notifications.** Signed webhooks (HMAC-SHA256) and Slack, delivered from a transactional outbox with retries and backoff.
- **Encryption at rest.** Secrets, channel credentials and action params are encrypted (Fernet, with key rotation). Configured fields are redacted from views and the audit log.
- **Runs anywhere.** One container; SQLite for trials, Postgres for production. Migrations, health/readiness probes, Prometheus metrics, JSON logs with request IDs, strict security headers and CSP.

**Integrations**
- **Python SDK** with typed outcomes and an LLM-friendly tool wrapper.
- **MCP server**: any MCP-capable agent (Claude Desktop, Claude Code, IDE agents) gets policy-checked tools with zero code.
- **Connectors**: Stripe (refunds, payment lookups), generic HTTP for any REST API, plus demo backends.

## Quickstart (5 minutes)

```bash
pip install -e ".[server,mcp]"
export AGENTGUARD_ENCRYPTION_KEYS=$(agentguard gen-key)
agentguard db upgrade
agentguard bootstrap --org "Acme" --email you@acme.com     # prompts for a password
agentguard serve
```

Open http://127.0.0.1:8080 and sign in. Your organization starts with a starter policy and demo connectors, so it works immediately:

```bash
python examples/support_agent_demo.py --email you@acme.com --password '...'
```

That registers agents and plays out: an auto-approved $18 refund, an idempotent retry, a $240 refund waiting for one approver, a $1,200 credit that needs two different admins, a blocked $5,000 refund, and a looping agent that trips the kill switch. Approve them under **Approvals**.

Production deployment with Docker and Postgres: see [docs/deployment.md](docs/deployment.md).

## Connect an agent

**Python SDK**

```python
from agentguard import AgentGuard, ActionBlocked, ApprovalPending

guard = AgentGuard("https://agentguard.example.com", api_key=os.environ["AGENTGUARD_KEY"])

with guard.run():  # groups one task's actions
    try:
        guard.act("stripe.refund",
                  {"payment_intent": "pi_123", "amount": 240, "currency": "usd", "reason": "requested_by_customer"},
                  idempotency_key="ticket-4822",      # safe to retry
                  context={"ticket": "4822"},          # shown to approvers
                  wait=False)
    except ApprovalPending as p:
        print("waiting for approval:", p.request_id)
    except ActionBlocked as b:
        print("blocked:", b.request["reason"])

refund_tool = guard.handler("stripe.refund")   # for LLM tool loops: returns outcomes instead of raising
tools = guard.tools()                          # JSON-schema tool definitions from the active policy
```

**MCP** (no code): `AGENTGUARD_URL=… AGENTGUARD_KEY=ag_… agentguard mcp`. For Claude Code:

```bash
claude mcp add agentguard --env AGENTGUARD_URL=https://agentguard.example.com --env AGENTGUARD_KEY=ag_... -- agentguard mcp
```

**HTTP**: `POST /v1/actions` with `Authorization: Bearer ag_…` and `{"action": "...", "params": {...}, "idempotency_key": "..."}`. Full API reference at `/docs` on your server.

## Writing policy

```yaml
connectors:
  stripe: {type: stripe, secret: stripe_key}     # stripe_key lives in Secrets, encrypted

policies:
  default: block
  rules:
    - id: refund-small
      agents: ["support-*"]
      action: stripe.refund
      when: {amount: {gt: 0, lte: 50}, currency: {eq: usd}}
      decision: allow
    - id: refund-large
      action: stripe.refund
      when: {amount: {gt: 500}}
      decision: review
      reason: Large refunds need two admins
      approvals: {min: 2, roles: [owner, admin]}
  rate_limits:
    - {id: refund-burst, action: stripe.refund, max: 5, window_seconds: 60, pause_agent: true}
```

Operators: `eq ne lt lte gt gte in not_in regex contains exists`, on nested paths like `customer.tier`. Validate in CI with `agentguard check-policy policy.yaml`, publish with the API or dashboard. Reference: [docs/policies.md](docs/policies.md).

## Documentation

- [Deployment](docs/deployment.md): Docker, Postgres, scaling, backups, upgrades
- [Configuration](docs/configuration.md): every environment variable
- [Policies](docs/policies.md): rules, approvals, rate limits, connectors
- [Integrations](docs/integrations.md): Slack approvals, webhooks and signature verification, MCP
- [Security](docs/security.md): threat model, guarantees and their limits

## Development

```bash
pip install -e ".[dev]"
pytest -q                                   # SQLite
AGENTGUARD_TEST_POSTGRES_URL=postgresql+psycopg://postgres@localhost/agentguard_test pytest -q   # + Postgres
ruff check agentguard tests
```

The suite (146 test runs across SQLite and Postgres) covers tenant isolation, role enforcement, the two-person rule, concurrent approvals, audit-chain tamper and truncation detection, Slack signature verification, encryption at rest, SSRF guards, migrations and the MCP server, on both databases.
