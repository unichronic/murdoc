#!/usr/bin/env python3
"""AgentVault HTTP gateway and control-plane API."""

import sys
import os
import csv
import hashlib
import io
import json
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bifrost_gateway import BifrostGateway
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from security.observability import install_observability
from security.control_plane import (
    alert_ledger,
    control_plane,
    decision_ledger,
    gateway_routes,
    runtime_settings,
    test_lab_config,
)
from security.policy_engine import (
    AuthEnvelope,
    ContextEnvelope,
)
from security.presidio_scanner import async_redact_output, async_scan_output, warmup_presidio
from security.config import (
    AGENT_BACKEND_TIMEOUT,
    AGENT_BACKEND_URL,
    AGENT_MEMORY_CONTEXT_URL,
)

import httpx


class ContextItem(BaseModel):
    content: str = ""
    source: str = "user"
    trust_level: str = ""
    can_answer: bool = True
    can_influence_goals: bool = False
    can_trigger_tools: bool = False


class ProcessRequest(BaseModel):
    text: str = ""
    contexts: list[ContextItem] = []
    auth: dict = {}
    request_id: str = ""
    route_id: str = "default-agent"
    tenant_id: str = "default"
    app_id: str = "default-app"
    user_id: str = ""


class RouteProfileRequest(BaseModel):
    description: str | None = None
    guardrails: dict[str, str] = {}
    policy_version: str | None = None
    config_version: str | None = None
    latency_budget_ms: int | None = None
    rate_limit_rpm: int | None = None
    monthly_budget_usd: float | None = None
    estimated_cost_per_1k_tokens_usd: float | None = None
    cache_read_only: bool | None = None
    rollout: str | None = None
    owner: str | None = None


class GatewayRouteRequest(BaseModel):
    upstream_url: str | None = None
    kind: str | None = None
    profile_id: str | None = None
    description: str | None = None
    strip_prefix: bool | None = None
    timeout_seconds: float | None = None
    owner: str | None = None


class TestLabConfigRequest(BaseModel):
    corpus_profile: str | None = None
    target: str | None = None
    mode: str | None = None
    iterations: int | None = None
    concurrency: int | None = None
    duration_seconds: int | None = None
    include_stateful: bool | None = None
    run_a2a_scanner: bool | None = None
    real_services: bool | None = None


class RuntimeSettingsRequest(BaseModel):
    lakera_required: bool | None = None
    lakera_confidence_threshold: float | None = None
    lakera_breakdown: bool | None = None
    nemo_guardrails_enabled: bool | None = None
    nemo_guardrails_required: bool | None = None
    nemo_guardrails_enforce: bool | None = None
    nemo_guardrails_max_retries: int | None = None
    nemo_guardrails_retry_backoff_seconds: float | None = None
    nemo_guardrails_skip_low_risk_reads: bool | None = None
    opa_fail_closed: bool | None = None
    opa_timeout_seconds: float | None = None


class FuzzRequest(BaseModel):
    profile: str | None = None


SENSITIVE_FORWARD_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def _safe_identifier(value: str | None, default: str = "") -> str:
    value = (value or "").strip()
    if not value:
        return default
    return value[:128]


def _api_key_fingerprint(request: Request) -> str:
    key_id = _safe_identifier(request.headers.get("X-API-Key-ID"))
    if key_id:
        return f"keyid:{key_id}"
    raw_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "")
    raw_key = raw_key.replace("Bearer ", "", 1).strip()
    if not raw_key:
        return ""
    return "sha256:" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]


def _forward_headers(request: Request) -> dict[str, str]:
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in SENSITIVE_FORWARD_HEADERS
    }


def _join_upstream_url(upstream_url: str, path: str = "") -> str:
    base = upstream_url.rstrip("/")
    suffix = path.lstrip("/")
    return f"{base}/{suffix}" if suffix else base


def _messages_to_text(payload: dict) -> str:
    messages = payload.get("messages", [])
    if not isinstance(messages, list):
        return json.dumps(payload, sort_keys=True)
    parts = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        role = item.get("role", "message")
        content = item.get("content", "")
        if isinstance(content, str):
            parts.append(f"{role}: {content}")
        else:
            parts.append(f"{role}: {json.dumps(content, sort_keys=True)}")
    return "\n".join(parts) or json.dumps(payload, sort_keys=True)


async def _gateway_preflight(
    bifrost: BifrostGateway,
    *,
    text: str,
    route_id: str,
    request: Request,
) -> JSONResponse | None:
    route_profile = bifrost.route_profile(route_id)
    outcome = await bifrost._preflight(
        text,
        contexts=[],
        auth=AuthEnvelope(),
        request_id=request.headers.get("X-Request-ID", ""),
        route_profile=route_profile,
        tenant_id=_safe_identifier(request.headers.get("X-Tenant-ID"), "default"),
        app_id=_safe_identifier(request.headers.get("X-App-ID"), "gateway-proxy"),
        user_id=_safe_identifier(request.headers.get("X-User-ID"), ""),
        api_key_fingerprint=_api_key_fingerprint(request),
    )
    if outcome.payload.get("blocked"):
        return JSONResponse(status_code=403, content=outcome.payload)
    return None


async def _egress_body(content: bytes, content_type: str) -> bytes:
    if not content:
        return content
    if not (content_type.startswith("text/") or "json" in content_type):
        return content
    text = content.decode("utf-8", errors="ignore")
    scan = await async_scan_output(text)
    if not scan.has_pii:
        return content
    clean = await async_redact_output(text)
    return clean.encode("utf-8")


async def _invoke_agent_backend(
    text: str,
    contexts: list[ContextEnvelope],
    auth: AuthEnvelope,
    request_id: str = "",
) -> dict:
    payload = {
        "text": text,
        "contexts": [context.to_dict() for context in contexts],
        "auth": auth.to_dict(),
        "request_id": request_id,
    }
    async with httpx.AsyncClient(timeout=AGENT_BACKEND_TIMEOUT) as client:
        response = await client.post(AGENT_BACKEND_URL, json=payload)
        response.raise_for_status()
        return response.json()


async def _load_backend_memory_contexts() -> list[ContextEnvelope]:
    if not AGENT_MEMORY_CONTEXT_URL:
        return []
    async with httpx.AsyncClient(timeout=AGENT_BACKEND_TIMEOUT) as client:
        response = await client.get(AGENT_MEMORY_CONTEXT_URL)
        response.raise_for_status()
        payload = response.json()
    contexts = []
    for item in payload.get("contexts", []):
        contexts.append(
            ContextEnvelope(
                content=item.get("content", ""),
                source=item.get("source", "memory"),
                trust_level=item.get("trust_level", ""),
                can_answer=bool(item.get("can_answer", True)),
                can_influence_goals=bool(item.get("can_influence_goals", False)),
                can_trigger_tools=bool(item.get("can_trigger_tools", False)),
            )
        )
    return contexts


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await warmup_presidio()
        yield

    app = FastAPI(title="AgentVault Gateway", lifespan=lifespan)
    obs = install_observability(app)
    app.state.control_plane = control_plane
    app.state.decision_ledger = decision_ledger
    app.state.alert_ledger = alert_ledger
    app.state.test_lab_config = test_lab_config
    app.state.runtime_settings = runtime_settings
    app.state.gateway_routes = gateway_routes
    bifrost = BifrostGateway(
        obs=obs,
        backend_invoker=_invoke_agent_backend if AGENT_BACKEND_URL else None,
        memory_loader=_load_backend_memory_contexts if AGENT_MEMORY_CONTEXT_URL else None,
        control_store=control_plane,
        ledger=decision_ledger,
    )

    repo_root = Path(__file__).resolve().parents[1]
    static_folder = str(repo_root / "ui" / "dist")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "service": "agentvault-gateway"}

    @app.get("/readyz")
    async def readyz():
        return {
            "status": "ready",
            "checks": bifrost.readiness_checks(),
            "profiles": {
                "active": "default-agent",
                "count": len(control_plane.list_profiles()),
            },
        }

    @app.get("/metrics")
    async def metrics():
        return obs.metrics_response()

    @app.get("/api/latency")
    async def latency():
        return {
            "source": "prometheus_histogram",
            "percentiles": obs.histogram_percentiles(),
        }

    @app.post("/v1/chat/completions")
    async def openai_chat_completions(request: Request):
        payload = await request.json()
        route_id = request.headers.get("X-AgentVault-Route") or payload.get("agentvault_route") or "default-llm"
        route = gateway_routes.get_route(route_id)
        if route is None or route.kind != "llm_openai":
            raise HTTPException(status_code=404, detail=f"LLM route not found: {route_id}")
        blocker = await _gateway_preflight(
            bifrost,
            text=_messages_to_text(payload),
            route_id=route.profile_id,
            request=request,
        )
        if blocker is not None:
            return blocker
        upstream = _join_upstream_url(route.upstream_url, "v1/chat/completions")
        body = {key: value for key, value in payload.items() if key != "agentvault_route"}
        async with httpx.AsyncClient(timeout=route.timeout_seconds) as client:
            upstream_response = await client.post(
                upstream,
                json=body,
                headers=_forward_headers(request),
            )
        content = await _egress_body(
            upstream_response.content,
            upstream_response.headers.get("content-type", ""),
        )
        return Response(
            content=content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
        )

    @app.api_route("/proxy/{route_id}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def http_proxy(route_id: str, path: str, request: Request):
        route = gateway_routes.get_route(route_id)
        if route is None or route.kind not in {"http_tool", "agent_http"}:
            raise HTTPException(status_code=404, detail=f"HTTP route not found: {route_id}")
        body = await request.body()
        preflight_text = "\n".join(
            [
                f"{request.method} /proxy/{route_id}/{path}",
                body.decode("utf-8", errors="ignore")[:8000],
            ]
        )
        blocker = await _gateway_preflight(
            bifrost,
            text=preflight_text,
            route_id=route.profile_id,
            request=request,
        )
        if blocker is not None:
            return blocker
        upstream = _join_upstream_url(route.upstream_url, path if route.strip_prefix else f"{route_id}/{path}")
        async with httpx.AsyncClient(timeout=route.timeout_seconds) as client:
            upstream_response = await client.request(
                request.method,
                upstream,
                params=request.query_params,
                content=body,
                headers=_forward_headers(request),
            )
        content = await _egress_body(
            upstream_response.content,
            upstream_response.headers.get("content-type", ""),
        )
        return Response(
            content=content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
        )

    @app.post("/api/process")
    async def process_request(body: ProcessRequest, request: Request):
        tenant_id = _safe_identifier(request.headers.get("X-Tenant-ID"), body.tenant_id or "default")
        app_id = _safe_identifier(request.headers.get("X-App-ID"), body.app_id or "default-app")
        user_id = _safe_identifier(request.headers.get("X-User-ID"), body.user_id or "")
        api_key_fingerprint = _api_key_fingerprint(request)
        contexts = [
            ContextEnvelope(
                content=item.content,
                source=item.source,
                trust_level=item.trust_level,
                can_answer=item.can_answer,
                can_influence_goals=item.can_influence_goals,
                can_trigger_tools=item.can_trigger_tools,
            )
            for item in body.contexts
        ]
        auth = AuthEnvelope(**body.auth) if body.auth else AuthEnvelope()
        outcome = await bifrost.process_request(
            body.text,
            contexts,
            auth,
            body.request_id,
            route_id=body.route_id,
            tenant_id=tenant_id,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
        )
        if outcome.status_code != 200:
            return JSONResponse(status_code=outcome.status_code, content=outcome.payload)
        return outcome.payload

    @app.get("/api/control-plane/profiles")
    async def list_route_profiles():
        return {"profiles": control_plane.list_profiles()}

    @app.get("/api/control-plane/profiles/{route_id}")
    async def get_route_profile(route_id: str):
        profile = control_plane.get_profile(route_id)
        if profile.route_id != route_id:
            raise HTTPException(status_code=404, detail="route profile not found")
        return profile.to_dict()

    @app.get("/api/control-plane/test-config")
    async def get_test_config():
        return test_lab_config.get_config().to_dict()

    @app.get("/api/control-plane/runtime-settings")
    async def get_runtime_settings():
        return runtime_settings.get_settings().to_dict()

    @app.put("/api/control-plane/runtime-settings")
    async def put_runtime_settings(body: RuntimeSettingsRequest):
        try:
            settings = runtime_settings.update_settings(body.model_dump(exclude_none=True))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return settings.to_dict()

    @app.put("/api/control-plane/test-config")
    async def put_test_config(body: TestLabConfigRequest):
        try:
            config = test_lab_config.update_config(body.model_dump(exclude_none=True))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return config.to_dict()

    @app.get("/api/control-plane/test-corpus")
    async def test_corpus():
        from tests.tools.attack_corpus import STATEFUL_SCENARIOS, build_payload_suite

        profiles = {}
        for profile_name in ("baseline", "extended"):
            payloads = build_payload_suite(profile_name)
            vectors: dict[str, int] = {}
            for payload in payloads:
                vectors[payload.vector] = vectors.get(payload.vector, 0) + 1
            profiles[profile_name] = {
                "payloads": len(payloads),
                "adversarial": sum(1 for payload in payloads if not payload.should_pass),
                "benign": sum(1 for payload in payloads if payload.should_pass),
                "vectors": vectors,
            }
        return {
            "profiles": profiles,
            "stateful_scenarios": [
                {
                    "id": scenario.scenario_id,
                    "vector": scenario.vector,
                    "description": scenario.description,
                    "steps": len(scenario.steps),
                }
                for scenario in STATEFUL_SCENARIOS
            ],
        }

    @app.get("/api/control-plane/test-targets")
    async def test_targets():
        return {
            "targets": [
                {
                    "id": "agno",
                    "label": "Single local agent",
                    "description": "Starts one intentionally vulnerable target agent for gateway-vs-raw comparison.",
                },
                {
                    "id": "multi-agent",
                    "label": "Coordinator plus peer",
                    "description": "Starts two live HTTP agents and validates agent-to-agent delegation side effects.",
                },
                {
                    "id": "agno-team",
                    "label": "Team target",
                    "description": "Starts the team-style target fixture used by the attack lab.",
                },
            ]
        }

    @app.post("/api/control-plane/test-run")
    async def run_configured_test_lab():
        config = test_lab_config.get_config()
        root = Path(__file__).resolve().parents[1]
        cmd = [
            sys.executable,
            str(root / "tests" / "tools" / "attack_lab.py"),
            "--profile",
            config.corpus_profile,
            "--target",
            config.target,
            "--mode",
            config.mode,
            "--iterations",
            str(config.iterations),
            "--concurrency",
            str(config.concurrency),
            "--json",
        ]
        if config.duration_seconds > 0:
            cmd.extend(["--duration-seconds", str(config.duration_seconds)])
        if config.include_stateful:
            cmd.append("--include-stateful")
        if config.run_a2a_scanner:
            cmd.append("--run-a2a-scanner")
        if config.real_services:
            cmd.append("--real-services")
        result = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(120, config.duration_seconds + 120),
        )
        try:
            payload = json.loads(result.stdout) if result.stdout.strip() else {}
        except ValueError:
            payload = {"raw_stdout": result.stdout}
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "config": config.to_dict(),
            "result": payload,
            "stderr": result.stderr[-4000:],
        }

    @app.put("/api/control-plane/profiles/{route_id}")
    async def put_route_profile(route_id: str, body: RouteProfileRequest):
        try:
            payload = body.model_dump(exclude_none=True)
            profile = control_plane.upsert_profile(route_id, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return profile.to_dict()

    @app.get("/api/control-plane/gateway-routes")
    async def list_gateway_routes():
        return {"routes": gateway_routes.list_routes()}

    @app.get("/api/control-plane/gateway-routes/{route_id}")
    async def get_gateway_route(route_id: str):
        route = gateway_routes.get_route(route_id)
        if route is None:
            raise HTTPException(status_code=404, detail="gateway route not found")
        return route.to_dict()

    @app.put("/api/control-plane/gateway-routes/{route_id}")
    async def put_gateway_route(route_id: str, body: GatewayRouteRequest):
        try:
            route = gateway_routes.upsert_route(route_id, body.model_dump(exclude_none=True))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return route.to_dict()

    @app.get("/api/control-plane/decision-ledger")
    async def list_decision_ledger(limit: int = 100):
        return {"records": decision_ledger.list_records(limit=limit)}

    @app.get("/api/control-plane/usage")
    async def usage_summary(tenant_id: str = "", app_id: str = ""):
        return decision_ledger.usage_summary(
            tenant_id=tenant_id or None,
            app_id=app_id or None,
        )

    @app.get("/api/control-plane/audit-export")
    async def audit_export(
        format: str = "json",
        limit: int = 100,
        tenant_id: str = "",
        app_id: str = "",
        route_id: str = "",
        decision: str = "",
    ):
        records = decision_ledger.query_records(
            limit=limit,
            tenant_id=tenant_id or None,
            app_id=app_id or None,
            route_id=route_id or None,
            decision=decision or None,
        )
        if format.lower() == "csv":
            fields = [
                "timestamp",
                "request_id",
                "tenant_id",
                "app_id",
                "user_id",
                "api_key_fingerprint",
                "route_id",
                "config_version",
                "policy_version",
                "decision",
                "blocked_layer",
                "reason",
                "violations",
                "duration_ms",
                "latency_budget_exceeded",
                "estimated_input_tokens",
                "estimated_output_tokens",
                "estimated_total_tokens",
                "estimated_cost_usd",
                "actual_input_tokens",
                "actual_output_tokens",
                "actual_total_tokens",
                "actual_cost_usd",
                "cost_usd",
                "usage_source",
                "cost_source",
                "provider",
                "model",
                "prompt_sha256",
            ]
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=fields)
            writer.writeheader()
            for record in records:
                row = {field: record.get(field, "") for field in fields}
                row["violations"] = ";".join(record.get("violations", []))
                writer.writerow(row)
            return Response(content=buffer.getvalue(), media_type="text/csv")
        if format.lower() != "json":
            raise HTTPException(status_code=400, detail="format must be json or csv")
        return {"records": records}

    @app.post("/api/control-plane/alerts")
    async def receive_alertmanager_webhook(payload: dict):
        record = alert_ledger.append(payload)
        if obs is not None:
            obs.security_event(
                "observability.alert.received",
                alert_id=record["alert_id"],
                status=record.get("status", ""),
                common_labels=record.get("common_labels", {}),
            )
        return {"status": "ok", "alert_id": record["alert_id"]}

    @app.get("/api/control-plane/alerts")
    async def list_alerts(limit: int = 100):
        return {"records": alert_ledger.list_records(limit)}

    @app.get("/api/control-plane/decision-ledger/{request_id}")
    async def get_decision_record(request_id: str):
        record = decision_ledger.get(request_id)
        if record is None:
            raise HTTPException(status_code=404, detail="decision record not found")
        return record

    @app.post("/api/fuzz")
    async def fuzz(body: FuzzRequest | None = None):
        from tests.tools.attack_corpus import build_payload_suite

        profile = (body.profile if body and body.profile else test_lab_config.get_config().corpus_profile).lower()
        try:
            payloads = build_payload_suite(profile)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        results = []
        for payload in payloads:
            text = payload.text
            contexts = [ContextEnvelope(**item) for item in payload.contexts]
            auth = AuthEnvelope(**payload.auth) if payload.auth else AuthEnvelope()
            evaluation = await bifrost.evaluate_payload(text, contexts, auth)

            results.append({
                'id': payload.payload_id,
                'vector': payload.vector,
                'description': payload.description,
                'should_pass': payload.should_pass,
                'blocked': evaluation['blocked'],
                'blocked_by': evaluation['blocked_by'],
                'pii_scrubbed': evaluation['pii_scrubbed'],
                'policy_action': evaluation['policy_action'],
                'policy_risk': evaluation['policy_risk'],
                'preview': text[:120] + ('...' if len(text) > 120 else ''),
            })

        adversarial = [r for r in results if not r['should_pass']]
        blocked_count = sum(1 for r in adversarial if r['blocked'])
        prevention_rate = round(blocked_count / max(len(adversarial), 1) * 100, 1)

        return {
            'results': results,
            'summary': {
                'total': len(results),
                'adversarial': len(adversarial),
                'blocked': blocked_count,
                'prevention_rate': prevention_rate,
                'owasp_pass': prevention_rate >= 95.0,
            }
        }

    @app.get("/api/stats")
    async def stats():
        try:
            total_req = blocked_req = pii_req = 0
            for metric in obs.registry.collect():
                if metric.name in ('agentvault_http_requests', 'agentvault_http_requests_total'):
                    for sample in metric.samples:
                        # Prometheus library generates metrics suffixed with _total for counters
                        if sample.name.endswith('_total') and sample.labels.get('route') == '/api/process':
                            total_req += int(sample.value)
                if metric.name in ('agentvault_security_decisions', 'agentvault_security_decisions_total'):
                    for sample in metric.samples:
                        if (
                            sample.name.endswith('_total')
                            and sample.labels.get('decision') == 'block'
                            and sample.labels.get('layer') == 'gateway'
                        ):
                            blocked_req += int(sample.value)
                if metric.name in ('agentvault_pii_entities_detected', 'agentvault_pii_entities_detected_total'):
                    for sample in metric.samples:
                        if sample.name.endswith('_total'):
                            pii_req += int(sample.value)
            return {
                'total_requests': total_req,
                'threats_blocked': blocked_req,
                'pii_entities_redacted': pii_req,
                'source': 'prometheus',
            }
        except Exception:
            return {'total_requests': 0, 'threats_blocked': 0, 'pii_entities_redacted': 0, 'source': 'unavailable'}

    @app.get("/")
    async def index():
        index_file = os.path.join(static_folder, 'index.html')
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse({"status": "UI build not found. Run 'npm run build'."})

    # Must be added last to avoid catching API routes
    if os.path.exists(static_folder):
        app.mount("/", StaticFiles(directory=static_folder, html=True), name="static")

    return app


app = create_app()

if __name__ == '__main__':
    print("=" * 70)
    print("AGENTVAULT GATEWAY (FastAPI / ASGI Adapter)")
    print("=" * 70)
    print()
    print("Starting web server...")
    print("  URL: http://localhost:8000")
    print("  Runtime Core: Bifrost")
    print()
    print("Open http://localhost:8000 in your browser")
    print("=" * 70)
    print()

    uvicorn.run("agentvault_gateway.app:app", host="0.0.0.0", port=8000, reload=False)
