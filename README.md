# AgentGuard

**An action gateway for AI agents.** Agents never hold the credentials for your payment, CRM or email systems. They ask AgentGuard to perform an action. AgentGuard checks it against policy, then executes it, routes it to a human for approval, or blocks it, and records every step in a tamper-evident audit log.

```
  AI agent ──(agent key only)──► AgentGuard ──(real credentials)──► Stripe / CRM / email / internal APIs
                                    │
                    policy: allow · review · block
                    approvals · rate limits · kill switch
                    hash-chained audit log
```

The point: **an SDK that only logs is advisory.** Enforcement is real only when the agent can't reach the downstream system without going through the gateway. That's why AgentGuard brokers the credentials.

## What's in v0.1

| Capability | How it works |
|---|---|
| **Credential brokering** | Connectors read secrets from the gateway's environment. Agents authenticate with their own scoped AgentGuard key and never see downstream credentials. |
| **Policy-as-code** | YAML rules match on agent (glob), action (glob) and param conditions (`lt`, `lte`, `gt`, `gte`, `eq`, `ne`, `in`, `not_in`, `regex`, `contains`, `exists`). **The most restrictive match wins**, so rule order can't weaken a decision. The default is `block`. |
| **Strict input validation** | Every action has a typed param schema. Wrong types, missing fields and unknown params are rejected, so `"amount": "10"` can't slip past an `amount <= 50` rule. |
| **Human approvals** | `review` decisions queue for a reviewer in the dashboard. Approval runs the action once. Concurrent double-approvals are rejected. Approvals expire after a TTL. Paused agents can't have actions approved. |
| **Rate limits + kill switch** | Per-agent sliding-window limits. `pause_agent: true` auto-pauses a looping agent, which blocks all of its actions until a human resumes it. |
| **Idempotency** | Requests carry an idempotency key. Retrying returns the original outcome instead of refunding twice, and the key is passed downstream (`Idempotency-Key` header). |
| **Tamper-evident audit** | Every transition (requested, evaluated, approved, executed, failed) is an append-only event chained by SHA-256. `GET /v1/admin/audit/verify` detects any edit or deletion. Configured sensitive params are redacted. |
| **Dashboard** | Approval queue, action list with per-action timelines, agents with pause/resume, audit verification and a policy simulator. All agent-supplied text is escaped, so a compromised agent can't inject script into a reviewer's browser. |
| **Python SDK** | `guard.act()` raises typed exceptions. `guard.handler()` returns LLM-readable outcomes for agent loops. `guard.tools()` returns JSON-schema tool definitions. `guard.run()` groups a task's actions under one run id. |

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Run the gateway with the example support-agent policy:

```bash
export PAYMENTS_API_KEY=sk_test_demo           # the gateway holds this, agents don't
export AGENTGUARD_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(24))")
agentguard check --config examples/agentguard.yaml
agentguard serve --config examples/agentguard.yaml
```

In another terminal, play out the scenarios (auto-allowed refund, refund waiting for a manager, blocked $5,000 refund, idempotent retry, looping agent tripping the kill switch):

```bash
python examples/support_agent_demo.py --admin-token "$AGENTGUARD_ADMIN_TOKEN"
```

Open http://127.0.0.1:8080/, sign in with the admin token, and approve or deny the pending refund. API docs are at `/docs`.

### With a real LLM agent

`examples/claude_support_agent.py` is a Claude-powered support agent. It loads its tool definitions from the gateway, and every tool call is executed by the gateway under policy:

```bash
pip install anthropic
agentguard create-agent support-claude --config examples/agentguard.yaml   # prints an agent key
export AGENTGUARD_KEY=ag_...
python examples/claude_support_agent.py "I'm cus_alice and was charged twice for \$18, please fix it"
```

## Using the SDK

```python
from agentguard import AgentGuard, ActionBlocked, ApprovalPending

guard = AgentGuard("http://127.0.0.1:8080", api_key=os.environ["AGENTGUARD_KEY"])

with guard.run():                                   # one run id per task
    guard.act("payments.get_customer", {"customer_id": "cus_alice"})
    try:
        guard.act("payments.refund",
                  {"customer_id": "cus_alice", "amount": 240},
                  idempotency_key="ticket-4822",    # safe to retry
                  context={"ticket": "4822", "rationale": "cancelled annual plan"},
                  wait=False)
    except ApprovalPending as p:
        print("manager review:", p.request_id)
    except ActionBlocked as b:
        print("blocked:", b.request["reason"])

refund_tool = guard.handler("payments.refund")      # for LLM tool loops; never raises on policy outcomes
```

## Writing policy

```yaml
policies:
  default: block
  rules:
    - id: refund-small
      agents: ["support-*"]
      action: payments.refund
      when: {amount: {gt: 0, lte: 50}}
      decision: allow
    - id: refund-medium
      action: payments.refund
      when: {amount: {gt: 50, lte: 500}}
      decision: review
      reason: Refunds over $50 require manager approval
  rate_limits:
    - id: refund-burst
      action: payments.refund
      max: 5
      window_seconds: 60
      pause_agent: true
```

Connectors: `mock_payments` and `mock_email` (in-memory, for demos and tests), plus `http`, a generic REST connector with path templating, URL-encoded path params, injected auth header and idempotency key. See `examples/agentguard.yaml`.

## API

| Audience | Endpoint | |
|---|---|---|
| Agent | `POST /v1/actions` | submit an action; returns decision, status and result |
| Agent | `GET /v1/actions/{id}` | poll your own action (e.g. awaiting approval) |
| Agent | `GET /v1/tools` | JSON-schema tool definitions for every brokered action |
| Admin | `GET/POST /v1/admin/agents`, `…/{id}/pause`, `…/resume`, `…/rotate-key` | agent registry and kill switch |
| Admin | `GET /v1/admin/approvals`, `POST …/{id}/approve`, `…/deny` | approval queue |
| Admin | `GET /v1/admin/actions`, `GET /v1/admin/actions/{id}` | history, with timeline |
| Admin | `GET /v1/admin/audit`, `GET /v1/admin/audit/verify` | audit log and integrity check |
| Admin | `GET /v1/admin/policies`, `POST /v1/admin/policies/simulate` | live policy and dry-run |

## Layout

```
agentguard/
  server/
    policy.py      policy engine (pure, no I/O)
    service.py     request lifecycle: validate → decide → approve → execute → audit
    connectors.py  credential-brokered connectors + strict param validation
    audit.py       hash-chained audit log + redaction
    db.py          SQLAlchemy models (SQLite dev, Postgres prod)
    app.py         FastAPI routes
    dashboard.html operator UI (no build step)
  sdk/client.py    Python SDK
  cli.py           agentguard check | serve | create-agent
examples/          policy file, scripted demo, Claude-powered agent
tests/             policy unit tests + end-to-end API tests
```

## Known limitations (MVP) and what's next

These are deliberate MVP shortcuts. Fix them before a real customer depends on the gateway:

- **Single process.** Audit sequencing uses an in-process lock. For multiple replicas, move to Postgres with an advisory lock (or a dedicated sequencer).
- **Crash during execution** leaves a request in `executing`. Add a reconciler that checks the downstream system by idempotency key.
- **Params are stored unencrypted** in the database (redaction applies to the audit log and API responses only). Add field-level encryption or a KMS envelope.
- **One admin token, no SSO/RBAC** for reviewers, and reviewer identity is self-asserted. Add per-reviewer accounts (WorkOS/Auth0), per-rule approver groups, and a separation-of-duties check.
- **Approvals are dashboard-only.** Slack/Teams approval cards are the most-requested next feature.
- **No MCP front door yet.** An MCP server that exposes brokered actions as MCP tools would let any MCP-capable agent use AgentGuard with zero code.
- **Secrets come from env vars.** Integrate a vault (AWS Secrets Manager, HashiCorp Vault) and per-agent OAuth on behalf of end users.
- **Observability export.** Emit OpenTelemetry spans per action so traces show up in the tools customers already use (LangSmith, Langfuse, Datadog).
