# Configuration

All configuration is through environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `AGENTGUARD_ENCRYPTION_KEYS` | **required** | Comma-separated Fernet keys (`agentguard gen-key`). The first encrypts; all decrypt, so you can rotate. |
| `AGENTGUARD_DATABASE_URL` | `sqlite:///agentguard.db` | SQLAlchemy URL. Production: `postgresql+psycopg://user:pass@host:5432/agentguard`. |
| `AGENTGUARD_PUBLIC_URL` | `http://127.0.0.1:8080` | URL people use to reach the dashboard. Used in Slack buttons, webhook payloads and invitation links. |
| `AGENTGUARD_ALLOW_SIGNUP` | `false` | Let anyone who can reach the server create an organization. For public SaaS only. |
| `AGENTGUARD_ALLOW_ENV_SECRETS` | `false` | Self-hosted only: allow connector configs to reference process env vars (`secret: env:NAME`). Never enable on a multi-tenant deployment: any org admin could read the host's environment. |
| `AGENTGUARD_ALLOW_PRIVATE_EGRESS` | `false` | Allow connectors and webhooks to call private, loopback and link-local addresses. Leave off unless you broker internal APIs, and then restrict egress at the network layer instead. |
| `AGENTGUARD_SESSION_TTL_HOURS` | `12` | Dashboard session lifetime. |
| `AGENTGUARD_INVITATION_TTL_HOURS` | `72` | Invitation link lifetime. |
| `AGENTGUARD_WORKER_ENABLED` | `true` | Run background jobs in the API process. Set `false` and run `agentguard worker` separately if you prefer. |
| `AGENTGUARD_WORKER_INTERVAL_SECONDS` | `5` | How often background jobs run. |
| `AGENTGUARD_STUCK_AFTER_SECONDS` | `300` | An execution that hasn't reported back after this long is marked `unknown`. |
| `AGENTGUARD_MAX_BODY_BYTES` | `1000000` | Request body limit. |
| `AGENTGUARD_AUTO_MIGRATE` | `true` | Apply database migrations on startup. |
| `AGENTGUARD_LOG_JSON` | `true` | JSON log lines (with request IDs). |

CLI-only:

| Variable | Purpose |
|---|---|
| `AGENTGUARD_BOOTSTRAP_PASSWORD` | Password for `agentguard bootstrap`, instead of the interactive prompt. |
| `AGENTGUARD_URL`, `AGENTGUARD_KEY` | Gateway URL and agent key for `agentguard mcp`. |
| `AGENTGUARD_MCP_WAIT` | `true` makes MCP tool calls wait for approval instead of returning `pending_approval`. |
| `AGENTGUARD_TEST_POSTGRES_URL` | Also run the test suite against this Postgres database. **It is wiped between tests.** |
