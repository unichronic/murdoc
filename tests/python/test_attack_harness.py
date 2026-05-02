import socket
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import requests

from tests.tools import agent_fuzzer
from tests.tools.attack_lab import _validate_real_service_layers
from tests.tools.attack_corpus import STATEFUL_SCENARIOS, build_payload_suite
from tests.tools.lab_env import build_gateway_env


ROOT = Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(url: str, timeout: float = 20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=1)
            if response.ok:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for {url}")


@pytest.fixture(scope="module")
def lab():
    agent_port = free_port()
    gateway_port = free_port()
    agent_runtime = tempfile.TemporaryDirectory(prefix="agentvault-harness-target-")
    agent_env = os.environ.copy()
    agent_env["AGENT_LAB_RUNTIME_DIR"] = agent_runtime.name

    agent_proc = subprocess.Popen(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "targets" / "agno_bot.py"), "--port", str(agent_port)],
        cwd=ROOT,
        env=agent_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    env = build_gateway_env(agent_port, gateway_port, real_services=False)
    env["AGENTVAULT_ALLOW_BODY_AUTH"] = "true"
    gateway_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "agentvault_gateway.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(gateway_port),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    try:
        wait_for(f"http://127.0.0.1:{agent_port}/healthz")
        wait_for(f"http://127.0.0.1:{gateway_port}/healthz")
        yield {
            "agent_url": f"http://127.0.0.1:{agent_port}",
            "gateway_url": f"http://127.0.0.1:{gateway_port}",
        }
    finally:
        gateway_proc.terminate()
        agent_proc.terminate()
        gateway_proc.wait(timeout=10)
        agent_proc.wait(timeout=10)
        agent_runtime.cleanup()


def test_attack_corpus_extended_expands_coverage():
    baseline = build_payload_suite("baseline")
    extended = build_payload_suite("extended")

    assert len(extended) > len(baseline)
    assert sum(1 for payload in baseline if payload.should_pass) >= 10
    assert STATEFUL_SCENARIOS


def test_fuzzer_extended_profile_blocks_gateway_core_attacks(lab):
    agent_fuzzer.AGENT_AUDIT = f"{lab['agent_url']}/audit"
    agent_fuzzer.AGENT_RESET = f"{lab['agent_url']}/reset"

    results = agent_fuzzer.run_fuzzer(
        f"{lab['gateway_url']}/api/process",
        profile="extended",
        iterations=1,
        concurrency=1,
    )
    summary = agent_fuzzer.summarize_results(results)

    assert summary["total"] >= len(build_payload_suite("extended"))
    assert summary["prevention_rate"] >= 95.0
    assert summary["false_positives"] == 0


def test_fuzzer_stateful_runner_catches_raw_memory_poisoning(lab):
    agent_fuzzer.AGENT_AUDIT = f"{lab['agent_url']}/audit"
    agent_fuzzer.AGENT_RESET = f"{lab['agent_url']}/reset"

    results = agent_fuzzer.run_stateful_scenarios(f"{lab['agent_url']}/process")

    assert len(results) == len(STATEFUL_SCENARIOS)
    expected_malicious = {scenario.scenario_id for scenario in STATEFUL_SCENARIOS if scenario.should_block}
    assert all(result.exploited for result in results if result.scenario_id in expected_malicious)
    assert all(not result.exploited for result in results if result.scenario_id not in expected_malicious)
    assert all(not result.blocked for result in results)


def test_fuzzer_stateful_runner_blocks_gateway_stateful_attacks(lab):
    agent_fuzzer.AGENT_AUDIT = f"{lab['agent_url']}/audit"
    agent_fuzzer.AGENT_RESET = f"{lab['agent_url']}/reset"

    results = agent_fuzzer.run_stateful_scenarios(f"{lab['gateway_url']}/api/process")

    assert len(results) == len(STATEFUL_SCENARIOS)
    expected_malicious = {scenario.scenario_id for scenario in STATEFUL_SCENARIOS if scenario.should_block}
    assert all(result.blocked for result in results if result.scenario_id in expected_malicious)
    assert all(not result.blocked for result in results if result.scenario_id not in expected_malicious)
    assert all(not result.exploited for result in results)


def test_soak_runner_interleaves_benign_payloads():
    payloads = build_payload_suite("extended")
    benign = [payload for payload in payloads if payload.should_pass]
    adversarial = [payload for payload in payloads if not payload.should_pass]

    ordered = []
    width = max(1, len(adversarial) // len(benign))
    adv_index = 0
    for benign_payload in benign:
        for _ in range(width):
            if adv_index < len(adversarial):
                ordered.append(adversarial[adv_index])
                adv_index += 1
        ordered.append(benign_payload)
    ordered.extend(adversarial[adv_index:])

    assert benign
    assert any(payload.should_pass for payload in ordered[:10])


def test_fuzzer_summary_fails_when_transport_or_service_errors_occur():
    result = agent_fuzzer.FuzzResult(
        payload_id="ERR-001",
        vector="transport",
        description="connection failed",
        should_pass=False,
        gateway_blocked=True,
        agent_exploited=False,
        gateway_status=0,
        latency_ms=0,
        error="Connection refused",
    )

    summary = agent_fuzzer.summarize_results([result])

    assert summary["errors"] == 1
    assert summary["owasp_pass"] is False


def test_fuzzer_marks_provider_layer_errors_as_run_errors(monkeypatch):
    payload = build_payload_suite("baseline")[0]

    def fake_fire_payload(url, payload, request_id):
        return (
            200,
            {
                "blocked": False,
                "layers": {
                    "semantic": {
                        "status": "error",
                        "message": "NeMo Guardrails unavailable: 429 rate limited",
                    }
                },
            },
            12.0,
        )

    monkeypatch.setattr(agent_fuzzer, "fire_payload", fake_fire_payload)

    result = agent_fuzzer.evaluate_payload("http://gateway.invalid", payload, reset_between=False)
    summary = agent_fuzzer.summarize_results([result])

    assert "semantic" in result.error
    assert summary["errors"] == 1
    assert summary["owasp_pass"] is False


def test_real_service_validation_rejects_disabled_layers_without_requiring_opa_url():
    errors = _validate_real_service_layers(
        {"checks": {"lakera": "disabled", "semantic": "disabled", "policy": "local-opa-compatible"}},
        {
            "layers": {
                "lakera": {"status": "pass", "message": "No injection detected\nRequest ID: unavailable"},
                "opa": {"status": "pass", "engine": "local"},
                "semantic": {"status": "disabled", "message": "NeMo Guardrails disabled"},
            }
        },
        {
            "LAKERA_API_KEY": "",
            "LAKERA_REQUIRED": "false",
            "OPA_POLICY_URL": "",
            "OPA_FAIL_CLOSED": "false",
            "NEMO_GUARDRAILS_ENABLED": "false",
            "NEMO_GUARDRAILS_REQUIRED": "false",
            "NVIDIA_API_KEY": "",
        },
    )

    assert any("LAKERA_API_KEY is missing" in item for item in errors)
    assert any("NeMo semantic layer" in item for item in errors)


def test_real_service_validation_rejects_http_opa_fallback_to_in_process_policy():
    errors = _validate_real_service_layers(
        {"checks": {"lakera": "configured", "semantic": "configured", "policy": "opa-http"}},
        {
            "layers": {
                "lakera": {"status": "pass", "message": "No injection detected"},
                "opa": {"status": "pass", "engine": "local"},
                "semantic": {"status": "pass", "message": "NeMo Guardrails semantic checks passed"},
            }
        },
        {
            "LAKERA_API_KEY": "key",
            "LAKERA_REQUIRED": "true",
            "OPA_POLICY_URL": "http://127.0.0.1:8181/v1/data/agentvault/decision",
            "OPA_FAIL_CLOSED": "true",
            "NEMO_GUARDRAILS_ENABLED": "true",
            "NEMO_GUARDRAILS_REQUIRED": "true",
            "NVIDIA_API_KEY": "key",
        },
    )

    assert any("configured local HTTP OPA" in item for item in errors)
