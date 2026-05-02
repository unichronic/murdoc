"""
Helpers for building local attack-lab environments.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(ROOT, ".env"))


REAL_SERVICES_ENV = "AGENTVAULT_USE_REAL_SERVICES"
STRICT_REAL_SERVICES_ENV = "AGENTVAULT_STRICT_REAL_SERVICES"


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def use_real_services(explicit: bool = False) -> bool:
    return explicit or env_flag(REAL_SERVICES_ENV, default=False)


def strict_real_services() -> bool:
    return env_flag(STRICT_REAL_SERVICES_ENV, default=True)


def build_gateway_env(agent_port: int, gateway_port: int, real_services: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    env["AGENT_BACKEND_URL"] = f"http://127.0.0.1:{agent_port}/process"
    env["AGENT_MEMORY_CONTEXT_URL"] = f"http://127.0.0.1:{agent_port}/memory_context"
    env["GATEWAY_PORT"] = str(gateway_port)

    if not real_services:
        # Deterministic local mode: keep the lab stable and independent of ambient secrets.
        env["LAKERA_API_KEY"] = ""
        env["LAKERA_REQUIRED"] = "false"
        env["NEMO_GUARDRAILS_ENABLED"] = "false"
        env["NEMO_GUARDRAILS_REQUIRED"] = "false"
        env["OPA_POLICY_URL"] = ""
        env["OPA_FAIL_CLOSED"] = "false"
    elif strict_real_services():
        # Real-service validation should fail visibly instead of falling back
        # or silently accepting unavailable provider checks.
        env["LAKERA_REQUIRED"] = "true"
        env["NEMO_GUARDRAILS_REQUIRED"] = "true"
        env.setdefault("AGENTVAULT_REQUEST_TIMEOUT", "45")
        if env.get("OPA_POLICY_URL", "").strip():
            env["OPA_FAIL_CLOSED"] = "true"

    return env
