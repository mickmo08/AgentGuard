"""A real LLM support agent whose every tool call goes through AgentGuard.

    pip install anthropic
    export ANTHROPIC_API_KEY=...          # or `ant auth login`
    export AGENTGUARD_KEY=ag_...          # from `agentguard create-agent support-claude`
    python examples/claude_support_agent.py "I was charged twice for $18 last week, can you fix it? I'm cus_alice"

The agent process holds two secrets: its Claude credential and its AgentGuard
key. It never holds the payments or CRM credentials. Tool definitions come
from the gateway, and tool calls are executed by the gateway under policy,
so a prompt-injected "refund $5,000" becomes a blocked request in the audit
log instead of a refund.
"""
from __future__ import annotations

import json
import os
import sys

import anthropic

from agentguard import AgentGuard

MODEL = "claude-opus-5-5"
SYSTEM = """You are a customer support agent for a SaaS company.
Use the tools to look up customers, issue refunds, add CRM notes and email customers.
Every tool call is checked by the company's policy gateway. If a tool result says an
action is pending approval, tell the customer a manager will review it; if it says the
action was blocked, do not try to work around the block, explain what happens next instead.
Never invent refund amounts: refund only what the customer was actually overcharged."""


def to_claude_tools(gateway_tools: list[dict]) -> tuple[list[dict], dict[str, str]]:
    """Gateway action names contain dots, which tool names don't allow; map them."""
    tools, names = [], {}
    for t in gateway_tools:
        tool_name = t["name"].replace(".", "__")
        names[tool_name] = t["name"]
        # The gateway validates params strictly (types, required, no extras) and returns
        # a readable error the model can correct, so tool-side strict mode isn't needed.
        tools.append({"name": tool_name, "description": t["description"] or t["name"], "input_schema": t["input_schema"]})
    return tools, names


def run(user_message: str) -> str:
    guard = AgentGuard(os.environ.get("AGENTGUARD_URL", "http://127.0.0.1:8080"), os.environ["AGENTGUARD_KEY"])
    client = anthropic.Anthropic()
    tools, names = to_claude_tools(guard.tools())
    messages: list[dict] = [{"role": "user", "content": user_message}]

    with guard.run() as run_id:  # every action in this conversation shares one run id
        for _ in range(20):  # hard cap on loop iterations
            response = client.beta.messages.create(
                model=MODEL,
                max_tokens=16000,
                system=SYSTEM,
                tools=tools,
                messages=messages,
                output_config={"effort": "medium"},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
            if response.stop_reason == "refusal":
                return "[the model declined this request]"
            if response.stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": response.content})
                continue
            if response.stop_reason != "tool_use":  # end_turn, max_tokens, stop_sequence
                return "".join(b.text for b in response.content if b.type == "text")

            messages.append({"role": "assistant", "content": response.content})
            results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                action = names.get(block.name)
                if action is None:
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": f"unknown tool {block.name}", "is_error": True})
                    continue
                # handler() never raises on policy outcomes; Claude reads blocked/pending results and adapts.
                outcome = guard.handler(action)(**block.input)
                print(f"  [{run_id}] {action}({json.dumps(block.input)}) -> {outcome['status']}", file=sys.stderr)
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(outcome), "is_error": not outcome["ok"] and outcome["status"] != "pending_approval"})
            messages.append({"role": "user", "content": results})  # all results in one message
    return "[stopped: too many tool iterations]"


if __name__ == "__main__":
    print(run(" ".join(sys.argv[1:]) or "Hi, I'm cus_bob. I cancelled my annual plan two weeks in; can I get the $240 back?"))
