"""agentguard command line.

    agentguard gen-key                       generate an encryption key
    agentguard db upgrade                    apply database migrations
    agentguard bootstrap --org Acme --email you@acme.com   create the first organization and owner
    agentguard serve [--host 0.0.0.0 --port 8080]          run the API, dashboard and worker
    agentguard worker                        run background jobs in a separate process
    agentguard create-agent --org acme support-bot          register an agent, print its key
    agentguard check-policy policy.yaml      validate a policy file (CI-friendly exit code)
    agentguard rotate-keys                   re-encrypt stored data under the primary key
    agentguard mcp                           MCP server over stdio for an agent (AGENTGUARD_URL, AGENTGUARD_KEY)

Configuration comes from AGENTGUARD_* environment variables (see docs/configuration.md).
"""
from __future__ import annotations

import argparse
import getpass
import os
import signal
import sys
import threading


def _settings():
    from agentguard.server.settings import Settings

    s = Settings.from_env()
    s.validate()
    return s


def _services(settings):
    """Build services without HTTP, for CLI commands that act directly on the database."""
    from agentguard.server.app import create_app

    app = create_app(settings, start_worker=False)
    return app.state


def cmd_gen_key(_: argparse.Namespace) -> int:
    from agentguard.server.crypto import generate_key

    print(generate_key())
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    from agentguard.server.db import make_engine
    from agentguard.server.migrate import current_revision, migrate

    engine = make_engine(os.environ.get("AGENTGUARD_DATABASE_URL", "sqlite:///agentguard.db"))
    if args.action == "upgrade":
        migrate(engine)
    print(f"database revision: {current_revision(engine)}")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    from agentguard.server.store import ApiError

    password = args.password or os.environ.get("AGENTGUARD_BOOTSTRAP_PASSWORD") or getpass.getpass("Owner password (12+ chars): ")
    state = _services(_settings())
    try:
        org, user = state.identity.create_org_with_owner(args.org, args.email, password, args.name)
    except ApiError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 1
    print(f"created organization {org['name']} ({org['slug']}) with owner {user['email']}")
    print(f"sign in at {state.settings.public_url}/")
    return 0


def cmd_create_agent(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from agentguard.server.auth import Principal
    from agentguard.server.db import Organization
    from agentguard.server.store import ApiError

    state = _services(_settings())
    with state.store.read() as s:
        org = s.execute(select(Organization).where((Organization.slug == args.org) | (Organization.id == args.org))).scalar_one_or_none()
    if org is None:
        print(f"error: organization {args.org!r} not found", file=sys.stderr)
        return 1
    cli = Principal("token", org.id, "owner", "cli")
    try:
        agent, key = state.gateway.create_agent(cli, args.slug, args.name, args.owner)
    except ApiError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 1
    print(f"created agent {agent['slug']} in {org.slug}")
    print(f"agent key (shown once): {key}")
    return 0


def cmd_check_policy(args: argparse.Namespace) -> int:
    from agentguard.server.config import PolicyError, parse_policy

    try:
        with open(args.file, encoding="utf-8") as fh:
            doc = parse_policy(fh.read())
    except (OSError, PolicyError) as exc:
        print(f"{args.file}: INVALID", file=sys.stderr)
        for err in getattr(exc, "errors", [str(exc)]):
            print(f"  - {err}", file=sys.stderr)
        return 2
    print(f"{args.file}: OK")
    print(f"  connectors: {', '.join(doc.connectors) or '(none)'}")
    print(f"  actions:    {', '.join(sorted(doc.all_actions())) or '(none)'}")
    print(f"  rules: {len(doc.policies.rules)}  rate limits: {len(doc.policies.rate_limits)}  default: {doc.policies.default}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from agentguard.server.app import create_app

    settings = _settings()
    app = create_app(settings)
    print(f"AgentGuard listening on http://{args.host}:{args.port}  (public URL {settings.public_url})")
    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=True, forwarded_allow_ips=args.forwarded_allow_ips, log_level="warning")
    return 0


def cmd_worker(_: argparse.Namespace) -> int:
    state = _services(_settings())
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print("worker running; Ctrl-C to stop")
    while not stop.is_set():
        try:
            state.worker.run_once()
        except Exception as exc:  # keep going
            print(f"worker iteration failed: {exc}", file=sys.stderr)
        stop.wait(state.settings.worker_interval_seconds)
    return 0


def cmd_rotate_keys(_: argparse.Namespace) -> int:
    from sqlalchemy import select

    from agentguard.server.db import ActionRequest, NotificationChannel, Secret

    state = _services(_settings())
    vault, n = state.gateway.vault, 0
    with state.store.tx_global() as s:
        for row in s.execute(select(Secret)).scalars():
            row.ciphertext = vault.rotate(row.ciphertext)
            n += 1
        for row in s.execute(select(NotificationChannel)).scalars():
            row.config_enc = vault.rotate(row.config_enc)
            n += 1
        for row in s.execute(select(ActionRequest)).scalars():
            row.params_enc = vault.rotate(row.params_enc)
            n += 1
    print(f"re-encrypted {n} values under the primary key; old keys can now be removed")
    return 0


def cmd_mcp(_: argparse.Namespace) -> int:
    from agentguard.mcp_server import main as mcp_main

    mcp_main()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description="Action gateway for AI agents")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("gen-key", help="generate an encryption key").set_defaults(fn=cmd_gen_key)
    p = sub.add_parser("db", help="database migrations")
    p.add_argument("action", choices=["upgrade", "current"])
    p.set_defaults(fn=cmd_db)
    p = sub.add_parser("bootstrap", help="create the first organization and its owner")
    p.add_argument("--org", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--name", default="")
    p.add_argument("--password", help="prefer AGENTGUARD_BOOTSTRAP_PASSWORD or the interactive prompt")
    p.set_defaults(fn=cmd_bootstrap)
    p = sub.add_parser("serve", help="run the API, dashboard and in-process worker")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--forwarded-allow-ips", default="127.0.0.1", help="proxies trusted for X-Forwarded-For")
    p.set_defaults(fn=cmd_serve)
    sub.add_parser("worker", help="run background jobs in this process").set_defaults(fn=cmd_worker)
    p = sub.add_parser("create-agent", help="register an agent and print its key")
    p.add_argument("--org", required=True, help="organization slug or id")
    p.add_argument("slug")
    p.add_argument("--name", default="")
    p.add_argument("--owner", default="")
    p.set_defaults(fn=cmd_create_agent)
    p = sub.add_parser("check-policy", help="validate a policy YAML file")
    p.add_argument("file")
    p.set_defaults(fn=cmd_check_policy)
    sub.add_parser("rotate-keys", help="re-encrypt stored data under the primary encryption key").set_defaults(fn=cmd_rotate_keys)
    sub.add_parser("mcp", help="MCP server over stdio (AGENTGUARD_URL, AGENTGUARD_KEY)").set_defaults(fn=cmd_mcp)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
