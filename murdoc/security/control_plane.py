"""Local control-plane state for routes, lab runs, and audit records."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from murdoc.security.config import (
    MURDOC_AUDIT_RETENTION_DAYS,
    MURDOC_CONTROL_PLANE_FILE,
    MURDOC_DECISION_LEDGER_FILE,
    MURDOC_DECISION_LEDGER_MAX_RECORDS,
    MURDOC_GATEWAY_ROUTES_FILE,
    MURDOC_RUNTIME_SETTINGS_FILE,
)


DEFAULT_POLICY_VERSION = os.getenv("MURDOC_POLICY_VERSION", "murdoc-local-v1")
DEFAULT_CONFIG_VERSION = os.getenv("MURDOC_CONFIG_VERSION", "local-default-v1")
DEFAULT_CONTROL_PLANE_FILE = MURDOC_CONTROL_PLANE_FILE
DEFAULT_DECISION_LEDGER_FILE = MURDOC_DECISION_LEDGER_FILE
DEFAULT_RUNTIME_SETTINGS_FILE = MURDOC_RUNTIME_SETTINGS_FILE

GUARDRAIL_MODES = {"disabled", "advisory", "enforce", "advisory_high_risk"}
TEST_CORPUS_PROFILES = {"baseline", "extended"}
TEST_TARGETS = {"agno", "multi-agent", "agno-team"}
TEST_MODES = {"gateway", "raw", "compare"}
GATEWAY_ROUTE_KINDS = {"llm_openai", "http_tool", "agent_http"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class RouteProfile:
    route_id: str
    description: str
    guardrails: dict[str, str]
    policy_version: str = DEFAULT_POLICY_VERSION
    config_version: str = DEFAULT_CONFIG_VERSION
    latency_budget_ms: int = 800
    rate_limit_rpm: int = 120
    monthly_budget_usd: float = 0.0
    estimated_cost_per_1k_tokens_usd: float = 0.0
    cache_read_only: bool = True
    rollout: str = "stable"
    owner: str = "local"
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def nemo_mode(self) -> str:
        return self.guardrails.get("nemo", "advisory_high_risk")

    def guardrail_mode(self, name: str, default: str = "enforce") -> str:
        return self.guardrails.get(name, default)


def _stable_config_version(route_id: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps({"route_id": route_id, **payload}, sort_keys=True, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"cfg-{digest}"


def _default_profiles() -> dict[str, RouteProfile]:
    common = {
        "lakera": "enforce",
        "presidio": "enforce",
        "policy": "enforce",
        "nemo": "advisory_high_risk",
    }
    return {
        "default-agent": RouteProfile(
            route_id="default-agent",
            description="Balanced default route for normal gateway traffic.",
            guardrails=dict(common),
            latency_budget_ms=800,
            monthly_budget_usd=0.0,
            estimated_cost_per_1k_tokens_usd=0.0,
        ),
        "read-only-low-risk": RouteProfile(
            route_id="read-only-low-risk",
            description="Low-risk read-only traffic; deterministic checks stay inline and NeMo runs only when risk signals require it.",
            guardrails={**common, "nemo": "advisory_high_risk"},
            latency_budget_ms=350,
            rate_limit_rpm=300,
            monthly_budget_usd=0.0,
            estimated_cost_per_1k_tokens_usd=0.0,
            cache_read_only=True,
        ),
        "tool-write": RouteProfile(
            route_id="tool-write",
            description="Tool calls and state-changing agent workflows.",
            guardrails={**common, "nemo": "advisory"},
            latency_budget_ms=1000,
            rate_limit_rpm=90,
            monthly_budget_usd=0.0,
            estimated_cost_per_1k_tokens_usd=0.0,
            cache_read_only=False,
        ),
        "admin-high-impact": RouteProfile(
            route_id="admin-high-impact",
            description="Approved admin operations that can export data or call external destinations.",
            guardrails={**common, "nemo": "enforce"},
            latency_budget_ms=1500,
            rate_limit_rpm=30,
            monthly_budget_usd=0.0,
            estimated_cost_per_1k_tokens_usd=0.0,
            cache_read_only=False,
        ),
        "mcp-tool": RouteProfile(
            route_id="mcp-tool",
            description="MCP tool interception profile.",
            guardrails={**common, "nemo": "advisory"},
            latency_budget_ms=700,
            rate_limit_rpm=120,
            monthly_budget_usd=0.0,
            estimated_cost_per_1k_tokens_usd=0.0,
            cache_read_only=False,
        ),
    }


class ControlPlaneStore:
    """Route snapshots read by the gateway hot path."""

    def __init__(self, config_file: str = DEFAULT_CONTROL_PLANE_FILE):
        self.config_file = config_file
        self._profiles: dict[str, RouteProfile] = _default_profiles()
        self._load_from_disk()

    def list_profiles(self) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in sorted(self._profiles.values(), key=lambda item: item.route_id)]

    def get_profile(self, route_id: str | None = None) -> RouteProfile:
        selected = (route_id or "default-agent").strip() or "default-agent"
        return self._profiles.get(selected) or self._profiles["default-agent"]

    def upsert_profile(self, route_id: str, data: dict[str, Any]) -> RouteProfile:
        existing = self.get_profile(route_id)
        guardrails = {**existing.guardrails, **data.get("guardrails", {})}
        invalid = {name: mode for name, mode in guardrails.items() if mode not in GUARDRAIL_MODES}
        if invalid:
            raise ValueError(f"Invalid guardrail modes: {invalid}")

        payload = {
            "description": data.get("description", existing.description),
            "guardrails": guardrails,
            "policy_version": data.get("policy_version", existing.policy_version),
            "latency_budget_ms": int(data.get("latency_budget_ms", existing.latency_budget_ms)),
            "rate_limit_rpm": int(data.get("rate_limit_rpm", existing.rate_limit_rpm)),
            "monthly_budget_usd": float(data.get("monthly_budget_usd", existing.monthly_budget_usd)),
            "estimated_cost_per_1k_tokens_usd": float(
                data.get("estimated_cost_per_1k_tokens_usd", existing.estimated_cost_per_1k_tokens_usd)
            ),
            "cache_read_only": bool(data.get("cache_read_only", existing.cache_read_only)),
            "rollout": data.get("rollout", existing.rollout),
            "owner": data.get("owner", existing.owner),
        }
        profile = RouteProfile(
            route_id=route_id,
            config_version=data.get("config_version") or _stable_config_version(route_id, payload),
            **payload,
        )
        self._profiles[route_id] = profile
        self._save_to_disk()
        return profile

    def _load_from_disk(self) -> None:
        if not self.config_file or not os.path.exists(self.config_file):
            return
        with open(self.config_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for item in data.get("profiles", []):
            route_id = item.get("route_id")
            if route_id:
                self.upsert_profile(route_id, item)

    def _save_to_disk(self) -> None:
        if not self.config_file:
            return
        directory = os.path.dirname(self.config_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.config_file, "w", encoding="utf-8") as handle:
            json.dump({"profiles": self.list_profiles()}, handle, indent=2, sort_keys=True)


@dataclass(frozen=True)
class GatewayRoute:
    route_id: str
    upstream_url: str
    kind: str = "http_tool"
    profile_id: str = "tool-write"
    description: str = ""
    strip_prefix: bool = True
    timeout_seconds: float = 30.0
    owner: str = "local"
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _default_gateway_routes() -> dict[str, GatewayRoute]:
    routes: dict[str, GatewayRoute] = {}
    default_llm = os.getenv("MURDOC_DEFAULT_LLM_UPSTREAM_URL", "").strip()
    if default_llm:
        routes["default-llm"] = GatewayRoute(
            route_id="default-llm",
            upstream_url=default_llm.rstrip("/"),
            kind="llm_openai",
            profile_id="default-agent",
            description="Default OpenAI-compatible LLM upstream.",
        )
    return routes


class GatewayRouteStore:
    """Upstream service registry for HTTP and OpenAI-compatible gateway modes."""

    def __init__(self, config_file: str = MURDOC_GATEWAY_ROUTES_FILE):
        self.config_file = config_file
        self._routes: dict[str, GatewayRoute] = _default_gateway_routes()
        self._load_from_disk()

    def list_routes(self) -> list[dict[str, Any]]:
        return [route.to_dict() for route in sorted(self._routes.values(), key=lambda item: item.route_id)]

    def get_route(self, route_id: str | None = None) -> GatewayRoute | None:
        selected = (route_id or "default-llm").strip() or "default-llm"
        return self._routes.get(selected)

    def upsert_route(self, route_id: str, data: dict[str, Any]) -> GatewayRoute:
        existing = self.get_route(route_id)
        upstream_url = str(data.get("upstream_url") or (existing.upstream_url if existing else "")).strip()
        if not upstream_url:
            raise ValueError("upstream_url is required")
        kind = str(data.get("kind") or (existing.kind if existing else "http_tool")).strip()
        if kind not in GATEWAY_ROUTE_KINDS:
            raise ValueError(f"kind must be one of {sorted(GATEWAY_ROUTE_KINDS)}")
        route = GatewayRoute(
            route_id=route_id,
            upstream_url=upstream_url.rstrip("/"),
            kind=kind,
            profile_id=str(data.get("profile_id") or (existing.profile_id if existing else "tool-write")),
            description=str(data.get("description") or (existing.description if existing else "")),
            strip_prefix=bool(data.get("strip_prefix", existing.strip_prefix if existing else True)),
            timeout_seconds=max(0.1, min(float(data.get("timeout_seconds", existing.timeout_seconds if existing else 30.0)), 300.0)),
            owner=str(data.get("owner") or (existing.owner if existing else "local")),
        )
        self._routes[route_id] = route
        self._save_to_disk()
        return route

    def _load_from_disk(self) -> None:
        if not self.config_file or not os.path.exists(self.config_file):
            return
        with open(self.config_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for item in data.get("routes", []):
            route_id = item.get("route_id")
            if route_id:
                self.upsert_route(route_id, item)

    def _save_to_disk(self) -> None:
        if not self.config_file:
            return
        directory = os.path.dirname(self.config_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.config_file, "w", encoding="utf-8") as handle:
            json.dump({"routes": self.list_routes()}, handle, indent=2, sort_keys=True)


class DecisionLedger:
    """Bounded in-memory decision ledger with optional JSONL persistence."""

    def __init__(
        self,
        max_records: int = MURDOC_DECISION_LEDGER_MAX_RECORDS,
        log_file: str = DEFAULT_DECISION_LEDGER_FILE,
        retention_days: int = MURDOC_AUDIT_RETENTION_DAYS,
    ):
        self.max_records = max_records
        self.log_file = log_file
        self.retention_days = max(1, retention_days)
        self._records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._load_from_disk()

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        request_id = record.get("request_id") or f"decision-{int(time.time() * 1000)}"
        stored = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **record,
            "request_id": request_id,
        }
        self._records[request_id] = stored
        self._records.move_to_end(request_id)
        if self._prune():
            self._compact_log_file()
        self._write(stored)
        return stored

    def list_records(self, limit: int = 100) -> list[dict[str, Any]]:
        if self._prune():
            self._compact_log_file()
        safe_limit = max(1, min(limit, self.max_records))
        return list(reversed(list(self._records.values())[-safe_limit:]))

    def query_records(
        self,
        *,
        limit: int = 100,
        tenant_id: str | None = None,
        app_id: str | None = None,
        route_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict[str, Any]]:
        records = self.list_records(limit=self.max_records)
        filtered = []
        for record in records:
            if tenant_id and record.get("tenant_id") != tenant_id:
                continue
            if app_id and record.get("app_id") != app_id:
                continue
            if route_id and record.get("route_id") != route_id:
                continue
            if decision and record.get("decision") != decision:
                continue
            filtered.append(record)
            if len(filtered) >= max(1, min(limit, self.max_records)):
                break
        return filtered

    def get(self, request_id: str) -> dict[str, Any] | None:
        if self._prune():
            self._compact_log_file()
        return self._records.get(request_id)

    def metadata(self) -> dict[str, Any]:
        if self._prune():
            self._compact_log_file()
        return {
            "persisted": bool(self.log_file),
            "retention_days": self.retention_days,
            "max_records": self.max_records,
            "record_count": len(self._records),
        }

    def usage_summary(self, *, tenant_id: str | None = None, app_id: str | None = None) -> dict[str, Any]:
        records = self.query_records(limit=self.max_records, tenant_id=tenant_id, app_id=app_id)
        summary: dict[tuple[str, str, str], dict[str, Any]] = {}
        for record in records:
            key = (
                record.get("tenant_id", "default"),
                record.get("app_id", "default-app"),
                record.get("route_id", "default-agent"),
            )
            entry = summary.setdefault(
                key,
                {
                    "tenant_id": key[0],
                    "app_id": key[1],
                    "route_id": key[2],
                    "requests": 0,
                    "blocked": 0,
                    "estimated_input_tokens": 0,
                    "estimated_output_tokens": 0,
                    "estimated_total_tokens": 0,
                    "estimated_cost_usd": 0.0,
                    "actual_total_tokens": 0,
                    "actual_cost_usd": 0.0,
                    "cost_usd": 0.0,
                    "latency_budget_exceeded": 0,
                    "rate_limit_rpm": record.get("rate_limit_rpm", 0),
                    "monthly_budget_usd": record.get("monthly_budget_usd", 0.0),
                },
            )
            entry["requests"] += 1
            if record.get("decision") == "block":
                entry["blocked"] += 1
            entry["estimated_input_tokens"] += int(record.get("estimated_input_tokens", 0))
            entry["estimated_output_tokens"] += int(record.get("estimated_output_tokens", 0))
            entry["estimated_total_tokens"] += int(record.get("estimated_total_tokens", 0))
            entry["estimated_cost_usd"] += float(record.get("estimated_cost_usd", 0.0))
            entry["actual_total_tokens"] += int(record.get("actual_total_tokens", 0))
            entry["actual_cost_usd"] += float(record.get("actual_cost_usd", 0.0))
            entry["cost_usd"] += float(record.get("cost_usd", 0.0))
            if record.get("latency_budget_exceeded"):
                entry["latency_budget_exceeded"] += 1
        rows = list(summary.values())
        for row in rows:
            row["estimated_cost_usd"] = round(row["estimated_cost_usd"], 6)
            row["actual_cost_usd"] = round(row["actual_cost_usd"], 6)
            row["cost_usd"] = round(row["cost_usd"], 6)
            budget = float(row.get("monthly_budget_usd") or 0.0)
            row["budget_used_pct"] = round(row["cost_usd"] / budget * 100, 2) if budget > 0 else 0.0
        totals = {
            "requests": sum(row["requests"] for row in rows),
            "blocked": sum(row["blocked"] for row in rows),
            "estimated_input_tokens": sum(row["estimated_input_tokens"] for row in rows),
            "estimated_output_tokens": sum(row["estimated_output_tokens"] for row in rows),
            "estimated_total_tokens": sum(row["estimated_total_tokens"] for row in rows),
            "estimated_cost_usd": round(sum(row["estimated_cost_usd"] for row in rows), 6),
            "actual_total_tokens": sum(row["actual_total_tokens"] for row in rows),
            "actual_cost_usd": round(sum(row["actual_cost_usd"] for row in rows), 6),
            "cost_usd": round(sum(row["cost_usd"] for row in rows), 6),
            "latency_budget_exceeded": sum(row["latency_budget_exceeded"] for row in rows),
        }
        return {"groups": rows, "totals": totals}

    def _write(self, record: dict[str, Any]) -> None:
        if not self.log_file:
            return
        directory = os.path.dirname(self.log_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.log_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")

    def _load_from_disk(self) -> None:
        if not self.log_file or not os.path.exists(self.log_file):
            return
        with open(self.log_file, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                request_id = record.get("request_id")
                if not request_id:
                    continue
                self._records[str(request_id)] = record
                self._records.move_to_end(str(request_id))
        if self._prune():
            self._compact_log_file()

    def _compact_log_file(self) -> None:
        if not self.log_file:
            return
        directory = os.path.dirname(self.log_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        temporary = f"{self.log_file}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            for record in self._records.values():
                handle.write(json.dumps(record, sort_keys=True))
                handle.write("\n")
        os.replace(temporary, self.log_file)

    def _parse_timestamp(self, record: dict[str, Any]) -> datetime:
        try:
            timestamp = datetime.fromisoformat(str(record.get("timestamp", "")).replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp

    def _prune(self) -> bool:
        changed = False
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        for request_id, record in list(self._records.items()):
            if self._parse_timestamp(record) < cutoff:
                self._records.pop(request_id, None)
                changed = True
        while len(self._records) > self.max_records:
            self._records.popitem(last=False)
            changed = True
        return changed


class AlertLedger:
    """Bounded store for Alertmanager webhook notifications."""

    def __init__(self, max_records: int = 500):
        self.max_records = max_records
        self._records: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        alert_id = f"alert-{int(time.time() * 1000)}-{len(self._records)}"
        stored = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "status": payload.get("status", ""),
            "group_labels": payload.get("groupLabels", {}),
            "common_labels": payload.get("commonLabels", {}),
            "common_annotations": payload.get("commonAnnotations", {}),
            "alerts": [
                {
                    "status": alert.get("status", ""),
                    "labels": alert.get("labels", {}),
                    "annotations": alert.get("annotations", {}),
                    "starts_at": alert.get("startsAt", ""),
                    "ends_at": alert.get("endsAt", ""),
                }
                for alert in payload.get("alerts", [])
                if isinstance(alert, dict)
            ],
        }
        self._records[alert_id] = stored
        self._records.move_to_end(alert_id)
        while len(self._records) > self.max_records:
            self._records.popitem(last=False)
        return stored

    def list_records(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, self.max_records))
        return list(reversed(list(self._records.values())[-safe_limit:]))


@dataclass(frozen=True)
class TestLabConfig:
    corpus_profile: str = "baseline"
    target: str = "agno"
    mode: str = "gateway"
    iterations: int = 1
    concurrency: int = 1
    duration_seconds: int = 0
    include_stateful: bool = False
    run_a2a_scanner: bool = False
    real_services: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TestLabConfigStore:
    """Small management snapshot for local red-team lab runs."""

    def __init__(self):
        self._config = TestLabConfig()

    def get_config(self) -> TestLabConfig:
        return self._config

    def update_config(self, data: dict[str, Any]) -> TestLabConfig:
        payload = {**self._config.to_dict(), **data}
        if payload["corpus_profile"] not in TEST_CORPUS_PROFILES:
            raise ValueError("corpus_profile must be baseline or extended")
        if payload["target"] not in TEST_TARGETS:
            raise ValueError("target must be agno, multi-agent, or agno-team")
        if payload["mode"] not in TEST_MODES:
            raise ValueError("mode must be gateway, raw, or compare")
        payload["iterations"] = max(1, min(int(payload["iterations"]), 20))
        payload["concurrency"] = max(1, min(int(payload["concurrency"]), 16))
        payload["duration_seconds"] = max(0, min(int(payload["duration_seconds"]), 600))
        payload["include_stateful"] = bool(payload["include_stateful"])
        payload["run_a2a_scanner"] = bool(payload["run_a2a_scanner"])
        payload["real_services"] = bool(payload["real_services"])
        self._config = TestLabConfig(**payload)
        return self._config


@dataclass(frozen=True)
class RuntimeSettings:
    lakera_required: bool = field(default_factory=lambda: _env_bool("LAKERA_REQUIRED", False))
    lakera_confidence_threshold: float = field(default_factory=lambda: _env_float("LAKERA_CONFIDENCE_THRESHOLD", 0.8))
    lakera_breakdown: bool = field(default_factory=lambda: _env_bool("LAKERA_BREAKDOWN", False))
    nemo_guardrails_enabled: bool = field(default_factory=lambda: _env_bool("NEMO_GUARDRAILS_ENABLED", False))
    nemo_guardrails_required: bool = field(default_factory=lambda: _env_bool("NEMO_GUARDRAILS_REQUIRED", False))
    nemo_guardrails_enforce: bool = field(default_factory=lambda: _env_bool("NEMO_GUARDRAILS_ENFORCE", False))
    nemo_guardrails_max_retries: int = field(default_factory=lambda: _env_int("NEMO_GUARDRAILS_MAX_RETRIES", 2))
    nemo_guardrails_retry_backoff_seconds: float = field(
        default_factory=lambda: _env_float("NEMO_GUARDRAILS_RETRY_BACKOFF_SECONDS", 2.0)
    )
    nemo_guardrails_skip_low_risk_reads: bool = field(
        default_factory=lambda: _env_bool("NEMO_GUARDRAILS_SKIP_LOW_RISK_READS", True)
    )
    opa_fail_closed: bool = field(default_factory=lambda: _env_bool("OPA_FAIL_CLOSED", False))
    opa_timeout_seconds: float = field(default_factory=lambda: _env_float("OPA_TIMEOUT_SECONDS", 1.0))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RuntimeSettingsStore:
    """Gateway-wide non-secret runtime knobs."""

    def __init__(self, config_file: str = DEFAULT_RUNTIME_SETTINGS_FILE):
        self.config_file = config_file
        self._settings = RuntimeSettings()
        self._load_from_disk()

    def get_settings(self) -> RuntimeSettings:
        return self._settings

    def update_settings(self, data: dict[str, Any]) -> RuntimeSettings:
        payload = {**self._settings.to_dict(), **data}
        payload["lakera_required"] = bool(payload["lakera_required"])
        payload["lakera_breakdown"] = bool(payload["lakera_breakdown"])
        payload["lakera_confidence_threshold"] = max(0.0, min(float(payload["lakera_confidence_threshold"]), 1.0))
        payload["nemo_guardrails_enabled"] = bool(payload["nemo_guardrails_enabled"])
        payload["nemo_guardrails_required"] = bool(payload["nemo_guardrails_required"])
        payload["nemo_guardrails_enforce"] = bool(payload["nemo_guardrails_enforce"])
        payload["nemo_guardrails_max_retries"] = max(0, min(int(payload["nemo_guardrails_max_retries"]), 5))
        payload["nemo_guardrails_retry_backoff_seconds"] = max(
            0.0,
            min(float(payload["nemo_guardrails_retry_backoff_seconds"]), 30.0),
        )
        payload["nemo_guardrails_skip_low_risk_reads"] = bool(payload["nemo_guardrails_skip_low_risk_reads"])
        payload["opa_fail_closed"] = bool(payload["opa_fail_closed"])
        payload["opa_timeout_seconds"] = max(0.05, min(float(payload["opa_timeout_seconds"]), 30.0))
        self._settings = RuntimeSettings(**payload)
        self._save_to_disk()
        return self._settings

    def _load_from_disk(self) -> None:
        if not self.config_file or not os.path.exists(self.config_file):
            return
        with open(self.config_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.update_settings(data.get("runtime_settings", data))

    def _save_to_disk(self) -> None:
        if not self.config_file:
            return
        directory = os.path.dirname(self.config_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.config_file, "w", encoding="utf-8") as handle:
            json.dump({"runtime_settings": self._settings.to_dict()}, handle, indent=2, sort_keys=True)


control_plane = ControlPlaneStore()
gateway_routes = GatewayRouteStore()
decision_ledger = DecisionLedger()
alert_ledger = AlertLedger()
test_lab_config = TestLabConfigStore()
runtime_settings = RuntimeSettingsStore()
