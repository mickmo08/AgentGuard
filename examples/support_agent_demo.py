"""Scripted customer-support agent hitting a running gateway.

    agentguard serve --config examples/agentguard.yaml          # terminal 1
    python examples/support_agent_demo.py --admin-token <token>  # terminal 2

It registers two agents and plays out the scenarios from the pitch:
a small refund (auto-allowed), a medium refund (waits for a manager),
a large refund (blocked), and a looping agent that trips the kill switch.
"""
from __future__ import annotations

import argparse
import uuid

from agentguard import AgentGuard, AgentGuardAdmin, AgentGuardError

GREEN, YELLOW, RED, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[0m"
COLORS = {"executed": GREEN, "pending_approval": YELLOW}


def show(label: str, req: dict) -> None:
    color = COLORS.get(req["status"], RED)
    status = req["status"] + (" (replay)" if req.get("replayed") else "")
    print(f"  {label:<50} {color}{status:<26}{RESET} {DIM}{req['rule_id'] or '-'}: {req['reason']}{RESET}")


def register(admin: AgentGuardAdmin, base: str, name: str, owner: str) -> AgentGuard:
    agent_id = f"{name}-{uuid.uuid4().hex[:4]}"
    created = admin.create_agent(agent_id, name=name.replace("-", " ").title(), owner=owner)
    return AgentGuard(base, created["api_key"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--admin-token", required=True)
    args = ap.parse_args()

    admin = AgentGuardAdmin(args.url, args.admin_token)
    bot = register(admin, args.url, "support-bot", "cx-team")

    print("\nTicket #4821: customer double-charged $18")
    with bot.run() as run_id:
        show("payments.get_customer(cus_alice)", bot.submit("payments.get_customer", {"customer_id": "cus_alice"}))
        show("payments.refund($18)", bot.submit("payments.refund", {"customer_id": "cus_alice", "amount": 18, "reason": "duplicate charge"},
                                                 idempotency_key="ticket-4821", context={"ticket": "4821"}))
        show("payments.refund($18) retried, same key", bot.submit("payments.refund", {"customer_id": "cus_alice", "amount": 18, "reason": "duplicate charge"},
                                                                  idempotency_key="ticket-4821", context={"ticket": "4821"}))
        show("email.send(confirmation)", bot.submit("email.send", {"to": "alice@example.com", "subject": "Refund issued", "body": "We refunded $18."}))
    print(f"  {DIM}run {run_id}: retry returned the original refund, nothing paid twice{RESET}")

    print("\nTicket #4822: annual plan cancellation, customer asks for $240 back")
    pending = bot.submit("payments.refund", {"customer_id": "cus_bob", "amount": 240, "reason": "cancelled annual plan"},
                         context={"ticket": "4822", "agent_rationale": "Customer cancelled 2 weeks into an annual plan; policy allows a prorated refund."})
    show("payments.refund($240)", pending)

    print("\nTicket #4823: prompt-injected email asks for a $5,000 'goodwill credit'")
    show("payments.refund($5,000)", bot.submit("payments.refund", {"customer_id": "cus_bob", "amount": 5000}))
    show("payments.delete_customer (not a configured action)", {"status": "rejected", "rule_id": None, "reason": _try(bot, "payments.delete_customer", {"customer_id": "cus_bob"})})

    print("\nA second agent gets stuck in a retry loop")
    loopy = register(admin, args.url, "support-loopy", "cx-team")
    for i in range(7):
        show(f"payments.refund($12) attempt {i + 1}", loopy.submit("payments.refund", {"customer_id": "cus_alice", "amount": 12}))

    print(f"\nAudit chain: {admin.verify_audit()}")
    print(f"\nOpen {args.url}/ and approve or deny the $240 refund ({pending['id']}) in the Approvals tab.\n")


def _try(bot: AgentGuard, action: str, params: dict) -> str:
    try:
        bot.submit(action, params)
        return "unexpectedly accepted"
    except AgentGuardError as exc:
        return str(exc)


if __name__ == "__main__":
    main()
