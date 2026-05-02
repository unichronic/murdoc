"""
Gateway observability primitives.

This module keeps metrics, traces, and structured security events centralized so
the gateway emits useful signals without leaking raw prompt or response data.
"""

import hashlib
import json
import logging
import os
import time
import uuid
import contextvars
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client import CONTENT_TYPE_LATEST

try:
    from opentelemetry import trace
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
except Exception:  # pragma: no cover - optional instrumentation fallback
    trace = None
    FastAPIInstrumentor = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None
    OTLPSpanExporter = None

try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
except ImportError:
    Request = None
    Response = None
    BaseHTTPMiddleware = object


SERVICE_NAME = "agentvault-gateway"
logger = logging.getLogger("agentvault.observability")
DEFAULT_EVENT_LOG_FILE = "logs/agentvault-events.jsonl"
DEFAULT_HISTOGRAM_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.075,
    0.1,
    0.25,
    0.5,
    0.75,
    1.0,
    2.5,
    5.0,
    7.5,
    10.0,
    float("inf"),
)

request_id_var = contextvars.ContextVar("request_id", default=None)
trace_id_var = contextvars.ContextVar("trace_id", default=None)


def configure_tracing(app):
    """Configure OpenTelemetry when available.

    The OTLP exporter is only attached when OTEL_EXPORTER_OTLP_ENDPOINT is set,
    which keeps local tests fast and avoids noisy connection errors.
    """
    if trace is None:
        return None

    if os.getenv("OTEL_SDK_DISABLED", "").lower() == "true":
        return trace.get_tracer(SERVICE_NAME)

    if TracerProvider and not getattr(configure_tracing, "_configured", False):
        resource = Resource.create({"service.name": SERVICE_NAME})
        provider = TracerProvider(resource=resource)
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
        if endpoint and OTLPSpanExporter and BatchSpanProcessor:
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        configure_tracing._configured = True

    if FastAPIInstrumentor and app:
        try:
            FastAPIInstrumentor.instrument_app(app)
        except Exception:
            pass

    return trace.get_tracer(SERVICE_NAME)


def trace_id_from_span():
    if trace is None:
        return None
    span = trace.get_current_span()
    context = span.get_span_context()
    if not context or not context.is_valid:
        return None
    return f"{context.trace_id:032x}"


def span_id_from_span():
    if trace is None:
        return None
    span = trace.get_current_span()
    context = span.get_span_context()
    if not context or not context.is_valid:
        return None
    return f"{context.span_id:016x}"


def prompt_fingerprint(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Observability:
    def __init__(self, app=None):
        self.app = app
        self.registry = CollectorRegistry()
        self.events = []
        self.tracer = configure_tracing(app) if app else None
        self.event_log_file = os.getenv("OBSERVABILITY_EVENT_LOG_FILE", DEFAULT_EVENT_LOG_FILE)

        self.http_requests = Counter(
            "agentvault_http_requests_total",
            "Total HTTP requests handled by the gateway.",
            ["route", "method", "status"],
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "agentvault_http_request_duration_seconds",
            "Gateway HTTP request duration in seconds.",
            ["route", "method", "status"],
            registry=self.registry,
        )
        self.security_decisions = Counter(
            "agentvault_security_decisions_total",
            "Security decisions by guardrail layer.",
            ["layer", "decision", "reason"],
            registry=self.registry,
        )
        self.layer_duration = Histogram(
            "agentvault_security_layer_duration_seconds",
            "Security guardrail layer duration in seconds.",
            ["layer", "decision"],
            registry=self.registry,
        )
        self.tier_duration = Histogram(
            "agentvault_security_tier_duration_seconds",
            "Security pipeline tier duration in seconds.",
            ["tier", "decision"],
            registry=self.registry,
        )
        self.security_errors = Counter(
            "agentvault_security_errors_total",
            "Security guardrail errors.",
            ["layer", "error_type"],
            registry=self.registry,
        )
        self.provider_events = Counter(
            "agentvault_security_provider_events_total",
            "Provider-specific security events.",
            ["provider", "outcome"],
            registry=self.registry,
        )
        self.gateway_decisions = Counter(
            "agentvault_gateway_decisions_total",
            "Final gateway decisions by route profile and policy version.",
            ["route_id", "decision", "reason", "policy_version"],
            registry=self.registry,
        )
        self.route_profile_info = Gauge(
            "agentvault_route_profile_info",
            "Active route profile metadata.",
            ["route_id", "config_version", "policy_version", "rollout"],
            registry=self.registry,
        )
        self.latency_budget_exceeded = Counter(
            "agentvault_latency_budget_exceeded_total",
            "Requests that exceeded the configured route latency budget.",
            ["route_id", "policy_version"],
            registry=self.registry,
        )
        self.usage_requests = Counter(
            "agentvault_usage_requests_total",
            "Gateway usage requests by tenant, app, route, and decision.",
            ["tenant_id", "app_id", "route_id", "decision"],
            registry=self.registry,
        )
        self.usage_tokens = Counter(
            "agentvault_usage_estimated_tokens_total",
            "Estimated token usage by tenant, app, route, and direction.",
            ["tenant_id", "app_id", "route_id", "direction"],
            registry=self.registry,
        )
        self.usage_cost = Counter(
            "agentvault_usage_estimated_cost_usd_total",
            "Estimated gateway cost in USD by tenant, app, and route.",
            ["tenant_id", "app_id", "route_id"],
            registry=self.registry,
        )
        self.actual_usage_tokens = Counter(
            "agentvault_usage_actual_tokens_total",
            "Provider-reported token usage by tenant, app, route, and direction.",
            ["tenant_id", "app_id", "route_id", "direction", "provider", "model"],
            registry=self.registry,
        )
        self.actual_usage_cost = Counter(
            "agentvault_usage_actual_cost_usd_total",
            "Provider-reported cost in USD by tenant, app, route, provider, and model.",
            ["tenant_id", "app_id", "route_id", "provider", "model"],
            registry=self.registry,
        )
        self.route_budget_info = Gauge(
            "agentvault_route_budget_info",
            "Route budget and rate-limit configuration.",
            ["route_id", "policy_version", "rate_limit_rpm", "monthly_budget_usd"],
            registry=self.registry,
        )
        self.pii_entities = Counter(
            "agentvault_pii_entities_detected_total",
            "PII entities detected by type and direction.",
            ["entity_type", "direction"],
            registry=self.registry,
        )

    def metrics_response(self):
        data = generate_latest(self.registry)
        if Response:
            return Response(content=data, media_type=CONTENT_TYPE_LATEST, status_code=200)
        return data, 200, {"Content-Type": CONTENT_TYPE_LATEST}

    def histogram_percentiles(self) -> dict[str, dict[str, dict[str, float | int | str]]]:
        return {
            "layer": self._histogram_summary("agentvault_security_layer_duration_seconds", "layer"),
            "tier": self._histogram_summary("agentvault_security_tier_duration_seconds", "tier"),
            "http": self._histogram_summary("agentvault_http_request_duration_seconds", "route"),
        }

    @contextmanager
    def span(self, name, **attrs):
        if self.tracer is None:
            yield None
            return
        with self.tracer.start_as_current_span(name) as span:
            for key, value in attrs.items():
                if value is not None:
                    span.set_attribute(key, value)
            yield span

    @contextmanager
    def layer(self, name, reason="none"):
        started = time.perf_counter()
        decision = "error"
        with self.span(f"security.{name}", security_layer=name):
            try:
                yield lambda value, next_reason="none": self._set_decision(
                    name, value, next_reason, started
                )
            except Exception as exc:
                error_type = exc.__class__.__name__
                self.security_errors.labels(name, error_type).inc()
                self.security_decisions.labels(name, "error", error_type).inc()
                self.layer_duration.labels(name, "error").observe(time.perf_counter() - started)
                self.security_event(
                    "security.layer.error",
                    layer=name,
                    decision="error",
                    reason=error_type,
                )
                raise
            finally:
                if decision == "error":
                    pass

    def _set_decision(self, layer, decision, reason, started):
        safe_reason = reason or "none"
        self.security_decisions.labels(layer, decision, safe_reason).inc()
        self.layer_duration.labels(layer, decision).observe(time.perf_counter() - started)
        self.security_event(
            "security.layer.completed",
            layer=layer,
            decision=decision,
            reason=safe_reason,
        )

    @contextmanager
    def tier(self, name):
        started = time.perf_counter()
        decision = "error"
        try:
            yield lambda value="pass": self._set_tier_decision(name, value, started)
        except Exception:
            self.tier_duration.labels(name, "error").observe(time.perf_counter() - started)
            raise
        finally:
            if decision == "error":
                pass

    def _set_tier_decision(self, tier, decision, started):
        self.tier_duration.labels(tier, decision).observe(time.perf_counter() - started)

    def record_provider_event(self, provider: str, outcome: str):
        self.provider_events.labels(provider, outcome).inc()

    def record_route_profile(self, profile):
        self.route_profile_info.labels(
            profile.route_id,
            profile.config_version,
            profile.policy_version,
            profile.rollout,
        ).set(1)
        self.route_budget_info.labels(
            profile.route_id,
            profile.policy_version,
            str(profile.rate_limit_rpm),
            str(profile.monthly_budget_usd),
        ).set(1)

    def record_gateway_decision(self, profile, decision: str, reason: str, duration_ms: float):
        safe_reason = reason or "none"
        self.gateway_decisions.labels(
            profile.route_id,
            decision,
            safe_reason,
            profile.policy_version,
        ).inc()
        if duration_ms > profile.latency_budget_ms:
            self.latency_budget_exceeded.labels(profile.route_id, profile.policy_version).inc()
            self.security_event(
                "gateway.latency_budget.exceeded",
                route_id=profile.route_id,
                config_version=profile.config_version,
                policy_version=profile.policy_version,
                latency_budget_ms=profile.latency_budget_ms,
                duration_ms=round(duration_ms, 3),
                decision=decision,
                reason=safe_reason,
            )

    def record_usage(self, record: dict[str, Any]):
        tenant_id = record.get("tenant_id", "default")
        app_id = record.get("app_id", "default-app")
        route_id = record.get("route_id", "default-agent")
        decision = record.get("decision", "allow")
        self.usage_requests.labels(tenant_id, app_id, route_id, decision).inc()
        self.usage_tokens.labels(tenant_id, app_id, route_id, "input").inc(
            int(record.get("estimated_input_tokens", 0))
        )
        self.usage_tokens.labels(tenant_id, app_id, route_id, "output").inc(
            int(record.get("estimated_output_tokens", 0))
        )
        self.usage_cost.labels(tenant_id, app_id, route_id).inc(
            float(record.get("estimated_cost_usd", 0.0))
        )
        provider = record.get("provider", "") or "unknown"
        model = record.get("model", "") or "unknown"
        self.actual_usage_tokens.labels(tenant_id, app_id, route_id, "input", provider, model).inc(
            int(record.get("actual_input_tokens", 0))
        )
        self.actual_usage_tokens.labels(tenant_id, app_id, route_id, "output", provider, model).inc(
            int(record.get("actual_output_tokens", 0))
        )
        self.actual_usage_cost.labels(tenant_id, app_id, route_id, provider, model).inc(
            float(record.get("actual_cost_usd", 0.0))
        )

    def _histogram_summary(self, metric_name: str, group_label: str) -> dict[str, dict[str, float | int | str]]:
        series: dict[str, dict[str, Any]] = {}
        for metric in self.registry.collect():
            if metric.name != metric_name:
                continue
            for sample in metric.samples:
                labels = dict(sample.labels)
                group = labels.get(group_label, "unknown")
                entry = series.setdefault(group, {"sum": 0.0, "count": 0, "buckets": {}})
                if sample.name.endswith("_sum"):
                    entry["sum"] += float(sample.value)
                elif sample.name.endswith("_count"):
                    entry["count"] += int(sample.value)
                elif sample.name.endswith("_bucket"):
                    le = labels.get("le", "")
                    entry["buckets"][le] = entry["buckets"].get(le, 0) + int(sample.value)
        output: dict[str, dict[str, float | int | str]] = {}
        for group, entry in series.items():
            count = int(entry["count"])
            avg_ms = round((entry["sum"] / count) * 1000, 1) if count else 0.0
            output[group] = {
                "count": count,
                "avg_ms": avg_ms,
                "p50_ms": self._estimate_percentile_ms(entry["buckets"], 0.50),
                "p95_ms": self._estimate_percentile_ms(entry["buckets"], 0.95),
                "p99_ms": self._estimate_percentile_ms(entry["buckets"], 0.99),
            }
        return output

    @staticmethod
    def _estimate_percentile_ms(buckets: dict[str, int], quantile: float) -> float | str:
        if not buckets:
            return 0.0
        total = max(buckets.values())
        if total <= 0:
            return 0.0
        target = total * quantile
        ordered = []
        for raw in buckets:
            if raw == "+Inf":
                ordered.append((float("inf"), buckets[raw]))
            else:
                try:
                    ordered.append((float(raw), buckets[raw]))
                except ValueError:
                    continue
        ordered.sort(key=lambda item: item[0])
        for upper, cumulative in ordered:
            if cumulative >= target:
                if upper == float("inf"):
                    return "inf"
                return round(upper * 1000, 1)
        upper = ordered[-1][0]
        if upper == float("inf"):
            return "inf"
        return round(upper * 1000, 1)

    def count_pii(self, result, direction):
        for entity_type in sorted(result.entity_types):
            count = sum(1 for entity in result.entities if entity.entity_type == entity_type)
            self.pii_entities.labels(entity_type, direction).inc(count)

    def security_event(self, event, **fields):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": fields.pop("level", "info"),
            "event": event,
            "service": SERVICE_NAME,
            "request_id": request_id_var.get(),
            "trace_id": trace_id_var.get() or trace_id_from_span(),
            "span_id": span_id_from_span(),
        }
        payload.update({key: value for key, value in fields.items() if value is not None})
        self.events.append(payload)
        serialized = json.dumps(payload, sort_keys=True)
        logger.info(serialized)
        self._write_event(payload, serialized)
        return payload

    def _write_event(self, payload, serialized):
        if not self.event_log_file:
            return
        directory = os.path.dirname(self.event_log_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.event_log_file, "a", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.write("\\n")


class ObservabilityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, obs: Observability):
        super().__init__(app)
        self.obs = obs

    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_var.set(req_id)

        tr_id_var = trace_id_from_span() or uuid.uuid4().hex
        trace_id_var.set(tr_id_var)

        start_time = time.perf_counter()
        if request.url.path != "/metrics":
            self.obs.security_event(
                "gateway.request.started",
                route=request.url.path,
                method=request.method,
            )

        response = await call_next(request)

        duration = time.perf_counter() - start_time

        # In FastAPI to get the matched route path we can use request.scope.get('route')
        route = request.scope.get('route')
        route_path = getattr(route, 'path', request.url.path)
        status = str(response.status_code)

        self.obs.http_requests.labels(route_path, request.method, status).inc()
        self.obs.http_duration.labels(route_path, request.method, status).observe(duration)

        response.headers["X-Request-ID"] = req_id
        response.headers["X-Trace-ID"] = tr_id_var

        if request.url.path != "/metrics":
            self.obs.security_event(
                "gateway.request.completed",
                route=route_path,
                method=request.method,
                status=status,
                duration_ms=round(duration * 1000, 3),
            )
        return response


def get_observability(app):
    return getattr(app.state, "observability", None)


def install_observability(app):
    obs = Observability(app)
    if hasattr(app, "state"):
        app.state.observability = obs
        if BaseHTTPMiddleware is not object:
            app.add_middleware(ObservabilityMiddleware, obs=obs)
    return obs
