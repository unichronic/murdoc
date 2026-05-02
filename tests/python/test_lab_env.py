from tests.tools.lab_env import REAL_SERVICES_ENV, STRICT_REAL_SERVICES_ENV, build_gateway_env, use_real_services


def test_build_gateway_env_defaults_to_deterministic_local_mode(monkeypatch):
    monkeypatch.setenv("LAKERA_API_KEY", "should-not-leak")
    env = build_gateway_env(8001, 8000, real_services=False)

    assert env["AGENT_BACKEND_URL"] == "http://127.0.0.1:8001/process"
    assert env["AGENT_MEMORY_CONTEXT_URL"] == "http://127.0.0.1:8001/memory_context"
    assert env["GATEWAY_PORT"] == "8000"
    assert env["LAKERA_API_KEY"] == ""
    assert env["LAKERA_REQUIRED"] == "false"
    assert env["NEMO_GUARDRAILS_ENABLED"] == "false"
    assert env["NEMO_GUARDRAILS_REQUIRED"] == "false"
    assert env["OPA_POLICY_URL"] == ""
    assert env["OPA_FAIL_CLOSED"] == "false"


def test_build_gateway_env_keeps_real_service_config_when_requested(monkeypatch):
    monkeypatch.setenv("LAKERA_API_KEY", "real-key")
    monkeypatch.setenv("NEMO_GUARDRAILS_ENABLED", "true")
    monkeypatch.setenv("OPA_POLICY_URL", "http://127.0.0.1:8181/v1/data/agentvault/allow")
    monkeypatch.setenv(STRICT_REAL_SERVICES_ENV, "false")

    env = build_gateway_env(9001, 9000, real_services=True)

    assert env["LAKERA_API_KEY"] == "real-key"
    assert env["NEMO_GUARDRAILS_ENABLED"] == "true"
    assert env["OPA_POLICY_URL"] == "http://127.0.0.1:8181/v1/data/agentvault/allow"


def test_build_gateway_env_forces_fail_visible_real_service_mode(monkeypatch):
    monkeypatch.setenv("LAKERA_API_KEY", "real-key")
    monkeypatch.setenv("NEMO_GUARDRAILS_ENABLED", "true")
    monkeypatch.setenv("NEMO_GUARDRAILS_REQUIRED", "false")
    monkeypatch.setenv("OPA_POLICY_URL", "http://127.0.0.1:8181/v1/data/agentvault/allow")
    monkeypatch.setenv("OPA_FAIL_CLOSED", "false")

    env = build_gateway_env(9001, 9000, real_services=True)

    assert env["LAKERA_REQUIRED"] == "true"
    assert env["NEMO_GUARDRAILS_REQUIRED"] == "true"
    assert env["OPA_FAIL_CLOSED"] == "true"


def test_use_real_services_honors_explicit_flag_and_env(monkeypatch):
    monkeypatch.delenv(REAL_SERVICES_ENV, raising=False)
    assert use_real_services(False) is False
    assert use_real_services(True) is True

    monkeypatch.setenv(REAL_SERVICES_ENV, "true")
    assert use_real_services(False) is True
