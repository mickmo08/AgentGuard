# Deploying AgentGuard

AgentGuard is one container (API + dashboard + background worker) plus a database. Use Postgres in production; SQLite is for trials and single-node installs.

## Docker Compose (single host)

```bash
cp .env.example .env
# set AGENTGUARD_ENCRYPTION_KEYS (agentguard gen-key), POSTGRES_PASSWORD, AGENTGUARD_PUBLIC_URL
docker compose up -d
docker compose exec agentguard agentguard bootstrap --org "Acme" --email you@acme.com
```

Put a TLS-terminating reverse proxy (Caddy, nginx, a cloud load balancer) in front of port 8080 and set `AGENTGUARD_PUBLIC_URL` to the HTTPS URL people use. The container trusts `X-Forwarded-For` from any proxy by default (`--forwarded-allow-ips "*"`); narrow it to your proxy's address if the container is reachable directly.

Building behind a TLS-intercepting corporate proxy: `docker build --secret id=pip_ca,src=/path/to/ca-bundle.crt .`

## Kubernetes / multiple replicas

- Run as many API replicas as you like against one Postgres. Writes are serialized per organization with a row lock (`SELECT … FOR UPDATE` on the organization), so the audit chain stays gap-free across replicas.
- The background worker (approval expiry, stuck-execution detection, notification delivery) is safe to run on every replica: state changes are conditional and deliveries are claimed with `SKIP LOCKED`. To isolate it, set `AGENTGUARD_WORKER_ENABLED=false` on API pods and run `agentguard worker` as its own deployment.
- Run migrations once per release as a job: `agentguard db upgrade` (and set `AGENTGUARD_AUTO_MIGRATE=false` on the pods), or leave auto-migrate on for small installs.
- Probes: liveness `GET /healthz`, readiness `GET /readyz` (checks the database).
- Metrics: `GET /metrics` (Prometheus). Restrict it to your monitoring network at the proxy or ingress; it exposes aggregate counts only.

## Sizing

Each action request is a few small writes. A single 2-vCPU instance on Postgres handles hundreds of actions per second; per-organization write serialization means one very busy tenant is bounded by its own lock, not by others. Connector latency (Stripe, your APIs) dominates end-to-end time and happens outside any lock.

## Backups and keys

- Back up Postgres as usual (PITR recommended). The audit chain verifies after a restore as long as the restore is consistent.
- **Back up `AGENTGUARD_ENCRYPTION_KEYS` separately from the database.** Without the key, stored secrets and action params cannot be decrypted; with the key and a database dump, they can. Keep it in your secret manager.
- Key rotation: put a new key first in `AGENTGUARD_ENCRYPTION_KEYS` (comma-separated, old keys after it), restart, run `agentguard rotate-keys`, then remove the old keys and restart again.

## Upgrades

1. Read the changelog.
2. `agentguard db upgrade` (or let auto-migrate run on start).
3. Roll the pods. Migrations are additive within a minor version, so old and new pods can run side by side during a rollout.

## First-run checklist

- [ ] HTTPS in front, `AGENTGUARD_PUBLIC_URL` set to it
- [ ] `AGENTGUARD_ALLOW_SIGNUP=false` unless you are running a public SaaS
- [ ] Encryption key stored in your secret manager and backed up
- [ ] Postgres backups enabled
- [ ] Egress: AgentGuard blocks connector and webhook calls to private addresses by default; also restrict outbound traffic at the network layer to the APIs you broker
- [ ] At least two owners, so losing one account doesn't lock you out
- [ ] Slack or a webhook configured, so approvals and alerts reach people
