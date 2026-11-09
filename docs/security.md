# Security model

## What AgentGuard guarantees

| Threat | Control |
|---|---|
| An agent (or a prompt injection steering it) tries an action the business didn't allow | The agent holds no downstream credentials. Every action is checked against the active policy; anything not explicitly allowed is blocked. Params are strictly typed, so type confusion can't satisfy an allow rule. |
| An agent loops and repeats an action | Per-agent rate limits block and can auto-pause the agent. Idempotency keys stop retries from executing twice. |
| One person approves a high-value action alone | Rules can require N distinct approvers from specific roles. The same person can't vote twice. API tokens can't approve. |
| An insider edits the audit trail | Per-organization SHA-256 hash chain; verification detects edits, deletions, reordering and truncation. Export it regularly to write-once storage to also detect a full rewrite. |
| Database dump or backup leak | Connector secrets, notification credentials and action params are encrypted with a key that is not stored in the database. Agent keys, API tokens, sessions and invitations are stored only as SHA-256 hashes; passwords use scrypt. |
| One tenant reads another's data | Every query is scoped by organization; tests cover cross-tenant access to actions, approvals, agents, audit and sessions. |
| Policy or webhook used to reach internal systems (SSRF) | Outbound calls to private, loopback, link-local and metadata addresses are refused by default; redirects are not followed; path params are URL-encoded. |
| Script injection into the approver's browser via agent-supplied text | The dashboard builds all DOM with text nodes (no HTML from data) and is served with a strict Content-Security-Policy (no inline script or style). Slack text is escaped. |
| Credential stuffing | Login throttling per email and per IP, constant-time comparisons, uniform timing for unknown emails, minimum password length. |

## Limits, stated plainly

- **AgentGuard enforces only what flows through it.** If an agent also holds a raw Stripe key, AgentGuard cannot stop it. Give agents AgentGuard keys only, and use restricted downstream keys scoped to what the connector needs.
- **Unknown outcomes.** If the gateway crashes after calling a downstream API but before recording the result, the action becomes `unknown`. AgentGuard does not guess: a person must check the downstream system. The idempotency key passed downstream prevents a duplicate if it is retried.
- **DNS rebinding.** The egress check resolves the host before the request; a hostile DNS server could answer differently a moment later. Restrict egress at the network layer for defense in depth.
- **Reviewer identity** comes from AgentGuard accounts (and Slack email matching for Slack votes). There is no SSO yet; protect owner accounts with strong, unique passwords.
- **Key custody.** Anyone with both the database and `AGENTGUARD_ENCRYPTION_KEYS` can decrypt stored secrets. Keep the key in a secret manager, separate from database backups.
- **Policy authors are trusted.** Admins can change policy and secrets; every change is versioned and audited, but an admin can grant broad permissions. Use the owner/admin split and review the audit log.

## Reporting a vulnerability

Email the maintainers privately rather than opening a public issue. Include steps to reproduce and the affected version.
