# Policies

A policy is a YAML document. Each organization has numbered, immutable versions; exactly one is active. Edit in the dashboard (Policies) or publish via API (`POST /v1/admin/policies`). Validate locally or in CI with `agentguard check-policy file.yaml`.

## How a request is decided

1. The agent must be active (a paused agent's requests are blocked with rule `agent-paused`).
2. The action must exist in the active policy and its params must match the schema exactly (types, required fields, enums, no extras).
3. **Rate limits** are checked; a tripped limit blocks, and with `pause_agent: true` also pauses the agent.
4. Every **rule** whose `agents`, `actions` and `when` all match is collected. **The most restrictive decision wins**: `block` > `review` > `allow`. Order never matters.
5. If no rule matches, `policies.default` applies (`block` unless you change it).

The decision, the matching rules and the policy version are recorded on the request and in the audit log. A request is always executed with the connector configuration of the policy version that decided it, even if the policy changes while it waits for approval.

## Document reference

```yaml
description: optional text
approval_ttl_seconds: 86400          # pending approvals expire after this (60s .. 30 days)
redact_params: [card_number, ssn]    # masked in views, notifications and the audit log (still sent to the connector)

connectors:
  <name>:
    type: stripe | http | mock_payments | mock_email
    secret: <secret name>             # stored under Secrets; never put credentials here
    base_url: https://...             # http (required), stripe (optional override)
    auth_header: Authorization        # http: header the secret goes in
    auth_scheme: Bearer               # http: prefix before the secret ("" for none)
    timeout_seconds: 10
    actions:                          # http: define your own; stripe/mock types have built-ins
      <action>:
        description: ...
        method: POST                  # GET | POST | PUT | PATCH | DELETE
        path: /customers/{customer_id}/notes   # {param} values are URL-encoded
        params:
          customer_id: {type: string}
          note: {type: string, required: true, description: ..., enum: [...]}

policies:
  default: block
  rules:
    - id: unique-id
      description: shown in the dashboard
      agents: ["support-*"]           # glob on the agent id (default "*")
      actions: ["stripe.refund"]      # glob on "<connector>.<action>"; `action:` works for one
      when:                           # all conditions must match
        amount: {gt: 50, lte: 500}
        customer.tier: {in: [gold, platinum]}
      decision: allow | review | block
      reason: shown to agents and approvers
      approvals:                      # used when decision is review
        min: 2                        # distinct people (1..5)
        roles: [owner, admin]         # who may approve (default: owner, admin, approver)
  rate_limits:
    - id: refund-burst
      agents: ["*"]
      actions: ["stripe.*"]
      max: 5
      window_seconds: 60
      pause_agent: true
```

Unknown keys are errors, so a typo like `wen:` fails validation instead of silently matching everything.

## Conditions

| Operator | Matches when |
|---|---|
| `eq`, `ne` | equal / not equal |
| `lt`, `lte`, `gt`, `gte` | numeric comparison; non-numbers never match |
| `in`, `not_in` | value is / isn't in a list |
| `regex` | full-string match (strings only) |
| `contains` | substring, or list membership |
| `exists` | `true`: the param is present; `false`: absent |

A condition on a missing param, or comparing incompatible types, does **not** match. Combined with `default: block`, malformed input can never satisfy an `allow` rule.

## Approvals when several review rules match

The strictest requirement of each kind applies: the highest `min`, and only roles that **every** matching rule allows. If the rules share no role, only owners may approve.

## Built-in connector actions

| Connector | Action | Params |
|---|---|---|
| `stripe` | `refund` | `payment_intent`, `amount` (major units, e.g. 12.50), `currency`, optional `reason` (duplicate, fraudulent, requested_by_customer) |
| `stripe` | `get_payment` | `payment_intent` |
| `mock_payments` | `refund`, `get_customer` | demo backend |
| `mock_email` | `send` | demo backend |

Stripe amounts are converted exactly (decimal arithmetic) to minor units, including zero-decimal (JPY) and three-decimal (KWD) currencies; an amount with too many decimal places is rejected rather than rounded. Use a Stripe **restricted key** limited to the permissions the connector needs.
