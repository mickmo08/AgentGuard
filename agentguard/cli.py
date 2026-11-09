"""agentguard CLI.

    agentguard check   --config agentguard.yaml
    agentguard serve   --config agentguard.yaml [--port 8080]
    agentguard create-agent support-bot --name "Support bot" --owner "cx-team"
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys


def _config_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default=os.environ.get("AGENTGUARD_CONFIG", "agentguard.yaml"))
    p.add_argument("--db", default=os.environ.get("AGENTGUARD_DATABASE_URL", "sqlite:///agentguard.db"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description="Action gateway for AI agents")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="validate a config file")
    _config_arg(p_check)

    p_serve = sub.add_parser("serve", help="run the gateway")
    _config_arg(p_serve)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)

    p_agent = sub.add_parser("create-agent", help="register an agent and print its API key")
    _config_arg(p_agent)
    p_agent.add_argument("agent_id")
    p_agent.add_argument("--name", default="")
    p_agent.add_argument("--owner", default="")

    args = parser.parse_args(argv)

    from agentguard.server.config import load_config
    from agentguard.server.policy import PolicyEngine

    try:
        config = load_config(args.config)
        PolicyEngine(config.policies)
    except Exception as exc:
        print(f"config error in {args.config}: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "check":
        print(f"{args.config}: OK")
        print(f"  connectors: {', '.join(config.connectors) or '(none)'}")
        print(f"  actions:    {', '.join(sorted(config.all_actions())) or '(none)'}")
        print(f"  rules: {len(config.policies.rules)}  rate limits: {len(config.policies.rate_limits)}  default: {config.policies.default}")
        missing = [c.secret_env for c in config.connectors.values() if c.secret_env and not os.environ.get(c.secret_env)]
        if missing:
            print(f"  warning: credentials not set in this environment: {', '.join(missing)}")
        return 0

    if args.cmd == "create-agent":
        from agentguard.server.db import make_sessionmaker
        from agentguard.server.service import Gateway, GatewayError

        gw = Gateway(config, make_sessionmaker(args.db))
        try:
            agent, key = gw.create_agent(args.agent_id, args.name, args.owner, actor="human:cli")
        except GatewayError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return 1
        print(f"created agent {agent['id']}")
        print(f"api key (shown once): {key}")
        return 0

    if args.cmd == "serve":
        import uvicorn

        from agentguard.server.app import create_app

        token = os.environ.get("AGENTGUARD_ADMIN_TOKEN")
        if not token:
            token = secrets.token_urlsafe(24)
            print(f"AGENTGUARD_ADMIN_TOKEN not set; generated one for this process:\n  {token}\n")
        app = create_app(config, args.db, admin_token=token)
        print(f"dashboard: http://{args.host}:{args.port}/   api docs: http://{args.host}:{args.port}/docs")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
