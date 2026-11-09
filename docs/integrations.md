# Integrations

## Slack approvals

Approval requests arrive in a Slack channel with **Approve** and **Deny** buttons. Votes from Slack follow the same rules as the dashboard (eligible roles, distinct people, minimum approvals) and are recorded with `via: slack`.

1. Create a Slack app. Bot token scopes: `chat:write`, `users:read`, `users:read.email`. Install it and invite it to your channel.
2. In AgentGuard → Integrations → **Add Slack channel**: the channel ID, the bot token (`xoxb-…`) and the app's signing secret.
3. Copy the **Interactivity Request URL** AgentGuard shows into your Slack app under *Interactivity & Shortcuts*.

A Slack user may decide only if their Slack email matches the email of a member of the organization with an eligible role. Requests are verified with Slack's signing secret and a 5-minute replay window. Agent-supplied text is escaped, so a request can't `@channel` or inject links.

## Webhooks

Add a webhook under Integrations. AgentGuard POSTs JSON for the events you choose:

| Event | When |
|---|---|
| `approval.requested` | an action needs approval |
| `approval.decided` | it was approved and executed, denied, or expired |
| `action.blocked` | policy blocked an action |
| `action.failed` | an allowed action failed downstream |
| `action.stuck` | an execution never reported back (outcome unknown) |
| `agent.paused` | an agent was paused (manually or by a rate limit) |

Each delivery carries `X-AgentGuard-Event` and `X-AgentGuard-Signature: t=<unix seconds>,v1=<hex>`, where `v1 = HMAC-SHA256(secret, "<t>." + raw_body)`. Verify it before trusting the payload:

```python
import hashlib, hmac, time

def verify(secret: str, body: bytes, header: str, tolerance: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    if abs(time.time() - int(parts["t"])) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))
```

Deliveries are written in the same database transaction as the event (outbox pattern) and retried with exponential backoff up to 10 attempts. Respond with any 2xx status. Delivery history is under Integrations → Recent deliveries.

## MCP

`agentguard mcp` is an MCP server over stdio that exposes the active policy's actions as tools (`payments.refund` becomes `payments__refund`). It holds only the agent's AgentGuard key.

```bash
# Claude Code
claude mcp add agentguard --env AGENTGUARD_URL=https://agentguard.example.com --env AGENTGUARD_KEY=ag_... -- agentguard mcp
```

```json
// Claude Desktop (claude_desktop_config.json)
{"mcpServers": {"agentguard": {"command": "agentguard", "args": ["mcp"],
  "env": {"AGENTGUARD_URL": "https://agentguard.example.com", "AGENTGUARD_KEY": "ag_..."}}}}
```

A `pending_approval` result is not an error; the tool text tells the model a person must approve. A `blocked` result is returned as an error and the server instructions tell the model not to work around it.

## Python SDK and HTTP

See the README. The OpenAPI reference is served at `/docs` on every AgentGuard server.
