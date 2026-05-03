"""
Shared Murdoc runtime gateway.

This module centralizes the security pipeline so both the normal HTTP gateway
and MCP tool interception use the same Murdoc request evaluation flow.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from collections import OrderedDict
from typing import Any, Awaitable, Callable

from murdoc.security.config import (
    LAKERA_API_KEY,
    LAKERA_REQUIRED,
    MURDOC_READ_CACHE_ENABLED,
    MURDOC_READ_CACHE_MAX_ITEMS,
    MURDOC_READ_CACHE_TTL_SECONDS,
    NEMO_GUARDRAILS_ENABLED,
    NEMO_GUARDRAILS_ENFORCE,
    NEMO_GUARDRAILS_REQUIRED,
    OPA_POLICY_URL,
    OPA_FAIL_CLOSED,
)
from murdoc.security.control_plane import (
    ControlPlaneStore,
    DecisionLedger,
    RouteProfile,
    control_plane,
    decision_ledger,
    runtime_settings,
)
from murdoc.security.lakera_guard import scan_prompt
from murdoc.security.observability import prompt_fingerprint
from murdoc.security.policy_engine import (
    AuthEnvelope,
    ContextEnvelope,
    PolicyDecision,
    PROMPT_INJECTION_RE,
    SENSITIVE_DOMAIN_RE,
    _extract_destinations,
    extract_semantic_intent,
    normalize_auth,
    evaluate_policy,
    sanitize_contexts_for_execution,
)
from murdoc.security.presidio_scanner import PresidioResult, async_redact_output, async_scan_output
from murdoc.security.semantic_guardrails import SemanticGuardrailResult, scan_semantics


BackendInvoker = Callable[[str, list[ContextEnvelope], AuthEnvelope, str], Awaitable[dict[str, Any]]]
MemoryLoader = Callable[[], Awaitable[list[ContextEnvelope]]]


@dataclass
class MurdocProcessOutcome:
    status_code: int
    payload: dict[str, Any]
    blocked_layer: str | None = None
    blocked_reason: str | None = None
    agent_input: str = ""
    contexts: list[ContextEnvelope] = field(default_factory=list)
    auth: AuthEnvelope = field(default_factory=AuthEnvelope)


@dataclass
class MurdocToolOutcome:
    blocked: bool
    blocked_layer: str | None
    blocked_reason: str | None
    message: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheEntry:
    payload: dict[str, Any]
    created_at: float


def _policy_layer_message(decision):
    if decision.action == "allow":
        return "Policy check passed\nStructured signals did not violate policy"
    if decision.action == "scrub":
        return "Policy allows request after PII redaction\nStructured signals require scrubbing"
    return f"Blocked by policy: {decision.reason}\nRisk: {decision.risk} ({decision.score})"


def _route_mode(route_profile: RouteProfile, name: str, default: str = "enforce") -> str:
    return route_profile.guardrail_mode(name, default)


@contextmanager
def _layer(obs, name: str):
    if obs is None:
        yield lambda *_args, **_kwargs: None
        return
    with obs.layer(name) as record:
        yield record


@contextmanager
def _tier(obs, name: str):
    if obs is None:
        yield lambda *_args, **_kwargs: None
        return
    with obs.tier(name) as record:
        yield record


def _lakera_advisory_reason(text: str, auth: AuthEnvelope) -> str | None:
    normalized = text.strip()
    lower = normalized.lower()
    effective_auth = normalize_auth(auth)
    intent = extract_semantic_intent(normalized, prompt_injection=False)
    corroborated = bool(PROMPT_INJECTION_RE.search(normalized))
    if corroborated:
        return None

    if (
        lower.startswith("remember ")
        and "prefer" in lower
        and not SENSITIVE_DOMAIN_RE.search(normalized)
        and not _extract_destinations(normalized)
    ):
        return "harmless_memory_preference"

    if (
        intent.user_goal == "information_request"
        and intent.requested_action == "read_only"
        and not _extract_destinations(normalized)
    ):
        return "read_only_information_request"

    documentation_terms = ("document", "documentation", "describe", "explain", "schema", "example")
    explicit_no_execution = (
        "without executing" in lower
        or "do not execute" in lower
        or "without running" in lower
        or "do not run" in lower
        or "no action" in lower
    )
    if (
        intent.requested_action == "read_only"
        and any(term in lower for term in documentation_terms)
        and explicit_no_execution
        and not intent.high_impact_action
        and not SENSITIVE_DOMAIN_RE.search(normalized)
        and not _extract_destinations(normalized)
    ):
        return "read_only_documentation_request"

    if (
        effective_auth.actor_role == "admin"
        and effective_auth.approved
        and intent.requested_action in {"data_export", "external_delivery"}
        and effective_auth.can_send_external
        and effective_auth.can_access_sensitive_data
    ):
        return "approved_admin_high_impact_flow"

    return None


def _should_preserve_authorized_action_parameters(text: str, auth: AuthEnvelope) -> bool:
    effective_auth = normalize_auth(auth)
    intent = extract_semantic_intent(text, prompt_injection=False)
    return (
        effective_auth.actor_role == "admin"
        and effective_auth.approved
        and intent.requested_action in {"data_export", "external_delivery"}
        and bool(intent.destinations)
        and effective_auth.can_access_sensitive_data
        and effective_auth.can_send_external
    )


def _semantic_skip_reason(
    text: str,
    contexts: list[ContextEnvelope],
    auth: AuthEnvelope,
    route_profile: RouteProfile | None = None,
) -> str | None:
    if route_profile and route_profile.nemo_mode == "disabled":
        return "disabled_by_route_profile"
    settings = runtime_settings.get_settings()
    if not settings.nemo_guardrails_skip_low_risk_reads:
        return None
    if settings.nemo_guardrails_enforce:
        return None
    if contexts:
        return None

    effective_auth = normalize_auth(auth)
    if effective_auth.approved or effective_auth.actor_role not in {"anonymous", "user"}:
        return None

    lower = text.lower()
    safe_read_phrase = (
        lower.startswith(("what is", "what are", "explain", "summarize", "please summarize", "look up", "point me to", "could you point"))
        or " policy" in lower
    )
    suspicious_content = any(term in lower for term in ("abuse", "abusive", "harass", "harassment", "phishing", "malware", "exploit"))
    if not safe_read_phrase or suspicious_content:
        return None

    intent = extract_semantic_intent(text, prompt_injection=False)
    if (
        intent.user_goal == "information_request"
        and intent.requested_action == "read_only"
        and not intent.destinations
        and not intent.data_objects
        and not intent.high_impact_action
        and not SENSITIVE_DOMAIN_RE.search(text)
    ):
        return "low_risk_read_only_after_primary_checks"
    return None


def _low_risk_after_primary_checks(
    text: str,
    contexts: list[ContextEnvelope],
    auth: AuthEnvelope,
    policy_decision,
    lakera_result,
    pii_input,
) -> bool:
    if getattr(policy_decision, "score", 0) > 0 or getattr(policy_decision, "violations", []):
        return False
    if getattr(lakera_result, "flagged", False):
        return False
    if getattr(pii_input, "has_pii", False):
        return False

    intent = extract_semantic_intent(text, prompt_injection=False)
    lower = text.lower()
    if any(term in lower for term in ("abuse", "abusive", "harass", "harassment", "phishing", "malware", "exploit")):
        return False
    if (
        intent.high_impact_action
        or intent.destructive_action
        or intent.destinations
        or intent.data_objects
        or intent.approval_bypass_attempt
        or SENSITIVE_DOMAIN_RE.search(text)
    ):
        return False

    effective_auth = normalize_auth(auth)
    if effective_auth.approved or effective_auth.actor_role not in {"anonymous", "user"}:
        return False

    for context in contexts:
        content = context.content or ""
        if context.can_influence_goals or context.can_trigger_tools:
            return False
        if PROMPT_INJECTION_RE.search(content) or SENSITIVE_DOMAIN_RE.search(content) or _extract_destinations(content):
            return False
    return True


def _estimate_tokens(text: str) -> int:
    stripped = (text or "").strip()
    if not stripped:
        return 0
    return max(1, (len(stripped) + 3) // 4)


def _extract_usage(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    usage = payload.get("usage")
    if usage is None and isinstance(payload.get("model_response"), dict):
        usage = payload["model_response"].get("usage")
    if usage is None and isinstance(payload.get("llm_response"), dict):
        usage = payload["llm_response"].get("usage")
    if not isinstance(usage, dict):
        return {}

    def number(*names: str) -> float | None:
        for name in names:
            value = usage.get(name)
            if isinstance(value, (int, float)):
                return float(value)
        return None

    input_tokens = number("input_tokens", "prompt_tokens")
    output_tokens = number("output_tokens", "completion_tokens")
    total_tokens = number("total_tokens")
    if total_tokens is None and (input_tokens is not None or output_tokens is not None):
        total_tokens = (input_tokens or 0) + (output_tokens or 0)
    cost_usd = number("cost_usd", "total_cost_usd", "estimated_cost_usd")
    return {
        "input_tokens": int(input_tokens) if input_tokens is not None else None,
        "output_tokens": int(output_tokens) if output_tokens is not None else None,
        "total_tokens": int(total_tokens) if total_tokens is not None else None,
        "cost_usd": float(cost_usd) if cost_usd is not None else None,
        "provider": usage.get("provider") or payload.get("provider") or payload.get("model_provider") or "",
        "model": usage.get("model") or payload.get("model") or payload.get("model_name") or "",
    }


class MurdocRuntime:
    def __init__(
        self,
        obs=None,
        backend_invoker: BackendInvoker | None = None,
        memory_loader: MemoryLoader | None = None,
        control_store: ControlPlaneStore | None = None,
        ledger: DecisionLedger | None = None,
    ):
        self.obs = obs
        self.backend_invoker = backend_invoker
        self.memory_loader = memory_loader
        self.control_store = control_store or control_plane
        self.ledger = ledger or decision_ledger
        self.response_cache: OrderedDict[str, CacheEntry] = OrderedDict()

    @staticmethod
    def readiness_checks() -> dict[str, str]:
        settings = runtime_settings.get_settings()
        lakera_status = "configured" if LAKERA_API_KEY else ("missing-required" if settings.lakera_required else "disabled")
        nemo_status = (
            "configured"
            if settings.nemo_guardrails_enabled
            else ("missing-required" if settings.nemo_guardrails_required else "disabled")
        )
        return {
            "runtime": "active",
            "lakera": lakera_status,
            "semantic": nemo_status,
            "policy": "opa-http" if OPA_POLICY_URL else "local-opa-compatible",
            "presidio": "lazy",
        }

    def route_profile(self, route_id: str | None = None) -> RouteProfile:
        profile = self.control_store.get_profile(route_id)
        if self.obs is not None:
            self.obs.record_route_profile(profile)
        return profile

    async def _load_contexts(self, contexts: list[ContextEnvelope]) -> list[ContextEnvelope]:
        loaded = list(contexts)
        if self.memory_loader is not None:
            loaded.extend(await self.memory_loader())
        return loaded

    @staticmethod
    def _cacheable_intent(
        text: str,
        contexts: list[ContextEnvelope],
        auth: AuthEnvelope,
        route_profile: RouteProfile | None = None,
    ) -> bool:
        if not MURDOC_READ_CACHE_ENABLED:
            return False
        if route_profile is not None and not route_profile.cache_read_only:
            return False
        if contexts:
            return False
        normalized_auth = normalize_auth(auth)
        if normalized_auth.approved:
            return False
        intent = extract_semantic_intent(text, prompt_injection=False)
        return (
            intent.user_goal == "information_request"
            and intent.requested_action == "read_only"
            and not intent.destinations
            and not intent.data_objects
        )

    @staticmethod
    def _cache_key(text: str, auth: AuthEnvelope, route_profile: RouteProfile | None = None) -> str:
        normalized_auth = normalize_auth(auth)
        return json.dumps(
            {
                "text": text.strip(),
                "actor_role": normalized_auth.actor_role,
                "approved": normalized_auth.approved,
                "route_id": route_profile.route_id if route_profile else "default-agent",
                "policy_version": route_profile.policy_version if route_profile else "",
                "config_version": route_profile.config_version if route_profile else "",
            },
            sort_keys=True,
        )

    def _get_cached_response(self, cache_key: str) -> dict[str, Any] | None:
        if not MURDOC_READ_CACHE_ENABLED:
            return None
        entry = self.response_cache.get(cache_key)
        if entry is None:
            return None
        if time.monotonic() - entry.created_at > MURDOC_READ_CACHE_TTL_SECONDS:
            self.response_cache.pop(cache_key, None)
            return None
        self.response_cache.move_to_end(cache_key)
        return json.loads(json.dumps(entry.payload))

    def _store_cached_response(self, cache_key: str, payload: dict[str, Any]) -> None:
        if not MURDOC_READ_CACHE_ENABLED:
            return
        self.response_cache[cache_key] = CacheEntry(
            payload=json.loads(json.dumps(payload)),
            created_at=time.monotonic(),
        )
        self.response_cache.move_to_end(cache_key)
        while len(self.response_cache) > MURDOC_READ_CACHE_MAX_ITEMS:
            self.response_cache.popitem(last=False)

    @staticmethod
    def _control_payload(
        route_profile: RouteProfile,
        tenant_id: str,
        app_id: str = "default-app",
        user_id: str = "",
        api_key_fingerprint: str = "",
    ) -> dict[str, Any]:
        return {
            "tenant_id": tenant_id or "default",
            "app_id": app_id or "default-app",
            "user_id": user_id or "",
            "api_key_fingerprint": api_key_fingerprint or "",
            "route_id": route_profile.route_id,
            "config_version": route_profile.config_version,
            "policy_version": route_profile.policy_version,
            "latency_budget_ms": route_profile.latency_budget_ms,
            "rate_limit_rpm": route_profile.rate_limit_rpm,
            "monthly_budget_usd": route_profile.monthly_budget_usd,
            "guardrails": dict(route_profile.guardrails),
            "rollout": route_profile.rollout,
        }

    def _record_decision(
        self,
        outcome: MurdocProcessOutcome,
        text: str,
        route_profile: RouteProfile,
        tenant_id: str,
        request_id: str | None,
        started: float,
        *,
        app_id: str = "default-app",
        user_id: str = "",
        api_key_fingerprint: str = "",
        usage: dict[str, Any] | None = None,
        tool_name: str | None = None,
    ) -> None:
        duration_ms = (time.perf_counter() - started) * 1000
        layers = outcome.payload.get("layers", {})
        blocked = bool(outcome.payload.get("blocked", False))
        reason = outcome.blocked_reason or outcome.payload.get("message") or "allowed"
        decision = "block" if blocked else "allow"
        layer_statuses = {
            name: layer.get("status", "unknown")
            for name, layer in layers.items()
            if isinstance(layer, dict)
        }
        violations = []
        opa = layers.get("opa")
        if isinstance(opa, dict):
            violations = list(opa.get("violations", []))
        usage = usage or {}
        usage_source = "provider" if usage.get("total_tokens") is not None else "estimate"
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        total_tokens = usage.get("total_tokens")
        if input_tokens is None:
            input_tokens = _estimate_tokens(text)
        if output_tokens is None:
            output_tokens = _estimate_tokens(outcome.payload.get("response", ""))
        if total_tokens is None:
            total_tokens = int(input_tokens) + int(output_tokens)
        cost_usd = usage.get("cost_usd")
        cost_source = "provider" if cost_usd is not None else "pricing_config" if route_profile.estimated_cost_per_1k_tokens_usd > 0 else "none"
        if cost_usd is None:
            cost_usd = (
                float(total_tokens) / 1000 * route_profile.estimated_cost_per_1k_tokens_usd
                if route_profile.estimated_cost_per_1k_tokens_usd > 0
                else 0.0
            )
        estimated_cost_usd = (
            float(total_tokens) / 1000 * route_profile.estimated_cost_per_1k_tokens_usd
            if route_profile.estimated_cost_per_1k_tokens_usd > 0
            else 0.0
        )
        record = {
            "request_id": request_id or "",
            "tenant_id": tenant_id or "default",
            "app_id": app_id or "default-app",
            "user_id": user_id or "",
            "api_key_fingerprint": api_key_fingerprint or "",
            "route_id": route_profile.route_id,
            "config_version": route_profile.config_version,
            "policy_version": route_profile.policy_version,
            "latency_budget_ms": route_profile.latency_budget_ms,
            "rate_limit_rpm": route_profile.rate_limit_rpm,
            "monthly_budget_usd": route_profile.monthly_budget_usd,
            "estimated_cost_per_1k_tokens_usd": route_profile.estimated_cost_per_1k_tokens_usd,
            "duration_ms": round(duration_ms, 3),
            "latency_budget_exceeded": duration_ms > route_profile.latency_budget_ms,
            "decision": decision,
            "blocked_layer": outcome.blocked_layer,
            "reason": reason,
            "prompt_sha256": prompt_fingerprint(text.strip()),
            "input_length": len(text.strip()),
            "usage_source": usage_source,
            "cost_source": cost_source,
            "provider": usage.get("provider", ""),
            "model": usage.get("model", ""),
            "estimated_input_tokens": int(input_tokens),
            "estimated_output_tokens": int(output_tokens),
            "estimated_total_tokens": int(total_tokens),
            "estimated_cost_usd": round(float(estimated_cost_usd), 8),
            "actual_input_tokens": int(input_tokens) if usage_source == "provider" else 0,
            "actual_output_tokens": int(output_tokens) if usage_source == "provider" else 0,
            "actual_total_tokens": int(total_tokens) if usage_source == "provider" else 0,
            "actual_cost_usd": round(float(cost_usd), 8) if cost_source == "provider" else 0.0,
            "cost_usd": round(float(cost_usd), 8),
            "layer_statuses": layer_statuses,
            "violations": violations,
            "pii_scrubbed": bool(outcome.payload.get("pii_scrubbed", False)),
            "tool_name": tool_name,
        }
        stored = self.ledger.append(record)
        outcome.payload["decision_id"] = stored["request_id"]
        if self.obs is not None:
            self.obs.record_gateway_decision(route_profile, decision, reason, duration_ms)
            self.obs.security_event(
                "gateway.decision.recorded",
                tenant_id=tenant_id or "default",
                app_id=app_id or "default-app",
                user_id=user_id or "",
                api_key_fingerprint=api_key_fingerprint or "",
                route_id=route_profile.route_id,
                config_version=route_profile.config_version,
                policy_version=route_profile.policy_version,
                decision=decision,
                reason=reason,
                blocked_layer=outcome.blocked_layer,
                duration_ms=round(duration_ms, 3),
                latency_budget_ms=route_profile.latency_budget_ms,
                usage_source=usage_source,
                cost_source=cost_source,
                provider=usage.get("provider", ""),
                model=usage.get("model", ""),
                estimated_total_tokens=int(total_tokens),
                estimated_cost_usd=round(float(cost_usd), 8),
                violations=violations,
                prompt_sha256=record["prompt_sha256"],
                tool_name=tool_name,
            )
            self.obs.record_usage(record)

    async def _preflight(
        self,
        text: str,
        contexts: list[ContextEnvelope],
        auth: AuthEnvelope,
        *,
        policy_text: str | None = None,
        request_id: str | None = None,
        route_profile: RouteProfile | None = None,
        tenant_id: str = "default",
        app_id: str = "default-app",
        user_id: str = "",
        api_key_fingerprint: str = "",
    ) -> MurdocProcessOutcome:
        route_profile = route_profile or self.route_profile()
        result = {
            "blocked": False,
            "pii_scrubbed": False,
            "layers": {},
            "response": "",
            "message": "",
            "gateway": "runtime",
            "control": self._control_payload(
                route_profile,
                tenant_id,
                app_id=app_id,
                user_id=user_id,
                api_key_fingerprint=api_key_fingerprint,
            ),
        }

        text = text.strip()
        lakera_mode = _route_mode(route_profile, "lakera")
        presidio_mode = _route_mode(route_profile, "presidio")
        policy_mode = _route_mode(route_profile, "policy")
        policy_enforced = policy_mode == "enforce"
        if not text:
            result["blocked"] = True
            result["message"] = "Request text is required"
            result["layers"]["lakera"] = {"status": "block", "message": "Request text is required"}
            if self.obs is not None:
                self.obs.security_decisions.labels("gateway", "block", "empty_request").inc()
                self.obs.security_event(
                    "murdoc.security.request.blocked",
                    layer="gateway",
                    decision="block",
                    reason="empty_request",
                )
            return MurdocProcessOutcome(400, result, blocked_layer="gateway", blocked_reason="empty_request")

        with _tier(self.obs, "tier0_ingress") as record_tier0:
            normalized_text = text
            loaded_contexts = contexts
            normalized_auth = auth
            record_tier0("pass")

        with _tier(self.obs, "tier1_blockers") as record_tier1:
            with _layer(self.obs, "lakera") as record_lakera:
                if lakera_mode == "disabled":
                    lakera_result = type("LakeraResult", (), {
                        "flagged": False,
                        "request_uuid": None,
                        "error": None,
                    })()
                    record_lakera("skipped", "disabled_by_route_profile")
                    result["layers"]["lakera"] = {
                        "status": "disabled",
                        "message": "Prompt attack scanner disabled by route profile",
                    }
                else:
                    lakera_result = await scan_prompt(normalized_text, request_id=request_id)
                    if self.obs is not None:
                        self.obs.security_event(
                            "murdoc.security.prompt.scanned",
                            layer="lakera",
                            prompt_sha256=prompt_fingerprint(normalized_text),
                            input_length=len(normalized_text),
                            provider_request_id=lakera_result.request_uuid or "unavailable",
                            provider_error=lakera_result.error,
                        )
        settings = runtime_settings.get_settings()
        if lakera_result.error and settings.lakera_required and lakera_mode == "enforce":
            record_lakera("block", "lakera_unavailable")
            record_tier1("block")
            result["blocked"] = True
            result["message"] = "Lakera Guard is required but not configured"
            result["layers"]["lakera"] = {
                "status": "error",
                "message": "Lakera Guard unavailable: LAKERA_API_KEY not configured",
            }
            result["layers"]["presidio_input"] = {"status": "pass", "message": "Skipped (Lakera unavailable)"}
            result["layers"]["opa"] = {"status": "pass", "message": "Skipped (Lakera unavailable)"}
            result["layers"]["presidio_output"] = {"status": "pass", "message": "Skipped (Lakera unavailable)"}
            if self.obs is not None:
                self.obs.security_decisions.labels("gateway", "block", "lakera_unavailable").inc()
                self.obs.security_event(
                    "murdoc.security.request.blocked",
                    layer="lakera",
                    decision="block",
                    reason="lakera_unavailable",
                )
            return MurdocProcessOutcome(503, result, blocked_layer="lakera", blocked_reason="lakera_unavailable")
        injection_detected = bool(lakera_result.flagged) and lakera_mode == "enforce"
        lakera_advisory_reason = None
        if lakera_result.flagged:
            lakera_advisory_reason = _lakera_advisory_reason(normalized_text, normalized_auth)
            if lakera_advisory_reason or lakera_mode != "enforce":
                injection_detected = False
        if lakera_mode == "disabled":
            pass
        elif injection_detected:
            if self.obs is not None:
                self.obs.record_provider_event("lakera", "block")
            record_lakera("block", "prompt_injection")
            record_tier1("block")
            result["layers"]["lakera"] = {
                "status": "block",
                "message": f"Blocked: Prompt injection detected\nRequest ID: {lakera_result.request_uuid or 'unavailable'}",
            }
        elif lakera_result.flagged:
            if self.obs is not None:
                self.obs.record_provider_event("lakera", "flag")
            advisory_reason = lakera_advisory_reason or "route_profile_advisory"
            record_lakera("flag", advisory_reason)
            result["layers"]["lakera"] = {
                "status": "flag",
                "message": (
                    "Lakera flagged request but it was downgraded to advisory mode\n"
                    f"Reason: {advisory_reason}\n"
                    f"Request ID: {lakera_result.request_uuid or 'unavailable'}"
                ),
            }
        else:
            if self.obs is not None:
                self.obs.record_provider_event("lakera", "error" if lakera_result.error else "pass")
            record_lakera("pass")
            result["layers"]["lakera"] = {
                "status": "pass",
                "message": f"No injection detected\nRequest ID: {lakera_result.request_uuid or 'unavailable'}",
            }

        with _layer(self.obs, "presidio_input") as record_presidio_input:
            if presidio_mode == "disabled":
                pii_input = PresidioResult(original_text=normalized_text)
                record_presidio_input("skipped", "disabled_by_route_profile")
                result["layers"]["presidio_input"] = {
                    "status": "disabled",
                    "message": "Sensitive data scanner disabled by route profile",
                }
                agent_input = normalized_text
            else:
                pii_input = await async_scan_output(normalized_text)
                if self.obs is not None:
                    self.obs.count_pii(pii_input, "input")
        if presidio_mode != "disabled" and pii_input.has_pii and presidio_mode == "enforce":
            record_presidio_input("scrub", "pii_detected")
            result["pii_scrubbed"] = True
            scrubbed_text = await async_redact_output(normalized_text)
            preserve_action_parameters = _should_preserve_authorized_action_parameters(normalized_text, normalized_auth)
            result["layers"]["presidio_input"] = {
                "status": "scrub",
                "message": (
                    f"PII detected and scrubbed\nEntities: {', '.join(pii_input.entity_types)}"
                    f'\nScrubbed: "{scrubbed_text}"'
                    + (
                        "\nExecution input preserved for approved high-impact action parameters"
                        if preserve_action_parameters
                        else ""
                    )
                ),
            }
            agent_input = normalized_text if preserve_action_parameters else scrubbed_text
            if self.obs is not None:
                self.obs.security_event(
                    "murdoc.security.pii.scrubbed",
                    layer="presidio_input",
                    decision="scrub",
                    reason="pii_detected",
                    direction="input",
                    entity_types=sorted(pii_input.entity_types),
                    entity_count=pii_input.entity_count,
                )
        elif presidio_mode != "disabled" and pii_input.has_pii:
            record_presidio_input("flag", "pii_detected")
            result["layers"]["presidio_input"] = {
                "status": "flag",
                "message": f"PII detected in input\nEntities: {', '.join(pii_input.entity_types)}",
            }
            agent_input = normalized_text
        elif presidio_mode != "disabled":
            record_presidio_input("pass")
            result["layers"]["presidio_input"] = {
                "status": "pass",
                "message": "No PII detected in input",
            }
            agent_input = normalized_text

        policy_subject = policy_text or normalized_text
        with _layer(self.obs, "opa") as record_opa:
            if policy_mode == "disabled":
                policy_decision = PolicyDecision(
                    action="allow",
                    allowed=True,
                    risk="disabled",
                    score=0,
                    reason="disabled_by_route_profile",
                    policy_engine="disabled",
                )
                record_opa("skipped", "disabled_by_route_profile")
            else:
                policy_decision = await evaluate_policy(
                    policy_subject,
                    lakera_result=lakera_result,
                    presidio_result=pii_input,
                    prompt_injection=injection_detected,
                    contexts=loaded_contexts,
                    auth=normalized_auth,
                )
                record_opa(
                    "pass" if policy_decision.action == "allow" else policy_decision.action,
                    policy_decision.reason,
                )

        result["layers"]["opa"] = {
            "status": (
                "disabled"
                if policy_mode == "disabled"
                else "pass"
                if policy_decision.action == "allow"
                else "flag"
                if not policy_enforced
                else policy_decision.action
            ),
            "message": _policy_layer_message(policy_decision),
            "risk": policy_decision.risk,
            "score": policy_decision.score,
            "violations": [violation.reason for violation in policy_decision.violations],
            "engine": policy_decision.policy_engine,
        }
        if not injection_detected and not policy_decision.allowed and policy_enforced:
            record_tier1("block")
        elif lakera_result.flagged or (not policy_decision.allowed and not policy_enforced):
            record_tier1("flag")
        else:
            record_tier1("pass")

        if injection_detected or (not policy_decision.allowed and policy_enforced):
            blocked_layer = "lakera" if injection_detected else "opa"
            blocked_reason = (
                "prompt_injection"
                if injection_detected
                else policy_decision.reason
            )
            result["blocked"] = True
            result["message"] = (
                f"Prompt injection detected (ID: {lakera_result.request_uuid or 'unavailable'})"
                if injection_detected
                else f"Policy violation detected: {policy_decision.reason}"
            )
            result["layers"]["presidio_output"] = {"status": "pass", "message": f"Skipped (blocked by {blocked_layer})"}
            result["layers"]["semantic"] = {
                "status": "skipped" if injection_detected else "skipped",
                "message": "Skipped after primary blocker decision",
            }
            if self.obs is not None:
                self.obs.security_decisions.labels("gateway", "block", blocked_reason).inc()
                self.obs.security_event(
                    "murdoc.security.request.blocked",
                    layer=blocked_layer,
                    decision="block",
                    reason=blocked_reason,
                    policy_risk=policy_decision.risk,
                    policy_score=policy_decision.score,
                )
            return MurdocProcessOutcome(
                200,
                result,
                blocked_layer=blocked_layer,
                blocked_reason=blocked_reason,
                agent_input=agent_input,
                contexts=loaded_contexts,
                auth=normalized_auth,
            )

        semantic_skip_reason = _semantic_skip_reason(normalized_text, loaded_contexts, normalized_auth, route_profile)
        if (
            not semantic_skip_reason
            and route_profile.nemo_mode == "advisory_high_risk"
            and _low_risk_after_primary_checks(
                normalized_text,
                loaded_contexts,
                normalized_auth,
                policy_decision,
                lakera_result,
                pii_input,
            )
        ):
            semantic_skip_reason = "low_risk_after_primary_checks"
        with _tier(self.obs, "tier2_semantic") as record_tier2:
            with _layer(self.obs, "semantic") as record_semantic:
                if semantic_skip_reason:
                    semantic_result = SemanticGuardrailResult(
                        blocked=False,
                        enabled=False,
                        reason=semantic_skip_reason,
                    )
                    record_semantic("skipped", semantic_skip_reason)
                    record_tier2("skipped")
                    result["layers"]["semantic"] = {
                        "status": "skipped",
                        "message": f"Skipped NeMo Guardrails: {semantic_skip_reason}",
                    }
                else:
                    semantic_result = await scan_semantics(normalized_text)
                    if self.obs is not None:
                        provider_outcome = "error" if semantic_result.error else ("block" if semantic_result.blocked else "pass")
                        if semantic_result.error and "429" in semantic_result.error:
                            provider_outcome = "rate_limit"
                        self.obs.record_provider_event("nemo_guardrails", provider_outcome)
                        self.obs.security_event(
                            "murdoc.security.semantic.scanned",
                            layer="semantic",
                            prompt_sha256=prompt_fingerprint(normalized_text),
                            provider="nemo_guardrails",
                            provider_error=semantic_result.error,
                            rail=semantic_result.rail or "",
                        )

            if semantic_skip_reason:
                pass
            else:
                settings = runtime_settings.get_settings()
                semantic_enforce = settings.nemo_guardrails_enforce or route_profile.nemo_mode == "enforce"
                semantic_unavailable = bool(semantic_result.error) or (
                    route_profile.nemo_mode == "enforce" and not semantic_result.enabled
                )
                semantic_fail_closed = semantic_enforce and (
                    settings.nemo_guardrails_required or route_profile.nemo_mode == "enforce"
                )
                if semantic_unavailable and semantic_fail_closed:
                    record_semantic("block", "semantic_guardrails_unavailable")
                    record_tier2("block")
                    result["blocked"] = True
                    result["message"] = "NeMo Guardrails is required but unavailable"
                    result["layers"]["semantic"] = {
                        "status": "error",
                        "message": f"NeMo Guardrails unavailable: {semantic_result.error or semantic_result.reason or 'disabled'}",
                    }
                    result["layers"]["presidio_output"] = {"status": "pass", "message": "Skipped (semantic guardrails unavailable)"}
                    if self.obs is not None:
                        self.obs.security_decisions.labels("gateway", "block", "semantic_guardrails_unavailable").inc()
                        self.obs.security_event(
                            "murdoc.security.request.blocked",
                            layer="semantic",
                            decision="block",
                            reason="semantic_guardrails_unavailable",
                        )
                    return MurdocProcessOutcome(
                        503,
                        result,
                        blocked_layer="semantic",
                        blocked_reason="semantic_guardrails_unavailable",
                        agent_input=agent_input,
                        contexts=loaded_contexts,
                        auth=normalized_auth,
                    )
                if semantic_result.error:
                    record_semantic("error", "semantic_guardrails_unavailable")
                    record_tier2("error")
                    result["layers"]["semantic"] = {
                        "status": "error",
                        "message": f"NeMo Guardrails unavailable: {semantic_result.error}",
                    }
                elif semantic_result.enabled and semantic_result.blocked:
                    record_semantic(
                        "block" if semantic_enforce else "flag",
                        semantic_result.reason or "semantic_policy_violation",
                    )
                    record_tier2("block" if semantic_enforce else "flag")
                    result["layers"]["semantic"] = {
                        "status": "block" if semantic_enforce else "flag",
                        "message": (
                            f"Blocked by NeMo Guardrails\nRail: {semantic_result.rail or 'unknown'}"
                            if semantic_enforce
                            else f"NeMo Guardrails flagged request\nRail: {semantic_result.rail or 'unknown'}"
                        ),
                    }
                elif semantic_result.enabled:
                    record_semantic("pass")
                    record_tier2("pass")
                    result["layers"]["semantic"] = {
                        "status": "pass",
                        "message": "NeMo Guardrails semantic checks passed",
                    }
                else:
                    record_semantic("pass")
                    record_tier2("pass")
                    result["layers"]["semantic"] = {
                        "status": "disabled",
                        "message": "NeMo Guardrails disabled",
                    }

        semantic_blocked = semantic_result.enabled and semantic_result.blocked and (
            runtime_settings.get_settings().nemo_guardrails_enforce or route_profile.nemo_mode == "enforce"
        )
        if semantic_blocked:
            result["blocked"] = True
            result["message"] = f"NeMo Guardrails blocked request ({semantic_result.rail or 'semantic'})"
            result["layers"]["presidio_output"] = {"status": "pass", "message": "Skipped (blocked by semantic)"}
            if self.obs is not None:
                self.obs.security_decisions.labels("gateway", "block", semantic_result.reason or "semantic_policy_violation").inc()
                self.obs.security_event(
                    "murdoc.security.request.blocked",
                    layer="semantic",
                    decision="block",
                    reason=semantic_result.reason or "semantic_policy_violation",
                    policy_risk=policy_decision.risk,
                    policy_score=policy_decision.score,
                )
            return MurdocProcessOutcome(
                200,
                result,
                blocked_layer="semantic",
                blocked_reason=semantic_result.reason or "semantic_policy_violation",
                agent_input=agent_input,
                contexts=loaded_contexts,
                auth=normalized_auth,
            )

        return MurdocProcessOutcome(
            200,
            result,
            agent_input=agent_input,
            contexts=loaded_contexts,
            auth=normalized_auth,
        )

    async def process_request(
        self,
        text: str,
        contexts: list[ContextEnvelope] | None = None,
        auth: AuthEnvelope | None = None,
        request_id: str = "",
        route_id: str | None = None,
        tenant_id: str = "default",
        app_id: str = "default-app",
        user_id: str = "",
        api_key_fingerprint: str = "",
    ) -> MurdocProcessOutcome:
        started = time.perf_counter()
        contexts = await self._load_contexts(contexts or [])
        auth = auth or AuthEnvelope()
        route_profile = self.route_profile(route_id)
        normalized_text = text.strip()
        cache_key = None
        if self._cacheable_intent(normalized_text, contexts, auth, route_profile):
            cache_key = self._cache_key(normalized_text, auth, route_profile)
            with _layer(self.obs, "cache") as record_cache:
                cached_payload = self._get_cached_response(cache_key)
                if cached_payload is not None:
                    record_cache("hit")
                    cached_payload.setdefault("layers", {})
                    cached_payload["control"] = self._control_payload(
                        route_profile,
                        tenant_id,
                        app_id=app_id,
                        user_id=user_id,
                        api_key_fingerprint=api_key_fingerprint,
                    )
                    cached_payload["layers"]["cache"] = {
                        "status": "hit",
                        "message": "Returned from exact-match read-only cache",
                    }
                    outcome = MurdocProcessOutcome(200, cached_payload)
                    self._record_decision(
                        outcome,
                        normalized_text,
                        route_profile,
                        tenant_id,
                        request_id,
                        started,
                        app_id=app_id,
                        user_id=user_id,
                        api_key_fingerprint=api_key_fingerprint,
                    )
                    return outcome
                record_cache("miss")
        preflight = await self._preflight(
            text,
            contexts,
            auth,
            request_id=request_id,
            route_profile=route_profile,
            tenant_id=tenant_id,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
        )
        if preflight.payload["blocked"]:
            preflight.payload.setdefault("layers", {})
            preflight.payload["layers"]["cache"] = {
                "status": "miss" if cache_key is not None else "bypass",
                "message": "Cache unavailable for this request",
            }
            self._record_decision(
                preflight,
                normalized_text,
                route_profile,
                tenant_id,
                request_id,
                started,
                app_id=app_id,
                user_id=user_id,
                api_key_fingerprint=api_key_fingerprint,
            )
            return preflight

        result = preflight.payload
        result.setdefault("layers", {})
        result["layers"]["cache"] = {
            "status": "miss" if cache_key is not None else "bypass",
            "message": "Cache not used before evaluation",
        }
        with _tier(self.obs, "tier3_execution") as record_tier3:
            with _layer(self.obs, "agent") as record_agent:
                usage = {}
                if self.backend_invoker is not None:
                    agent_result = await self.backend_invoker(
                        preflight.agent_input,
                        sanitize_contexts_for_execution(preflight.contexts),
                        preflight.auth,
                        request_id,
                    )
                    usage = _extract_usage(agent_result)
                    agent_response = agent_result.get("response") or json.dumps(agent_result, sort_keys=True)
                    result["agent"] = {
                        "tool_calls": agent_result.get("tool_calls", []),
                        "mode": "backend",
                        "usage": usage,
                    }
                else:
                    agent_response = (
                        f"I received your query: '{preflight.agent_input}'. "
                        "This is a simulated response from the AI agent."
                    )
                    result["agent"] = {"tool_calls": [], "mode": "simulated"}
                record_agent("pass")
                record_tier3("pass")

        with _tier(self.obs, "tier4_egress") as record_tier4:
            with _layer(self.obs, "presidio_output") as record_presidio_output:
                presidio_mode = _route_mode(route_profile, "presidio")
                if presidio_mode == "disabled":
                    pii_output = PresidioResult(original_text=agent_response)
                    record_presidio_output("skipped", "disabled_by_route_profile")
                    result["layers"]["presidio_output"] = {
                        "status": "disabled",
                        "message": "Sensitive data scanner disabled by route profile",
                    }
                    result["response"] = agent_response
                    record_tier4("skipped")
                else:
                    pii_output = await async_scan_output(agent_response)
                    if self.obs is not None:
                        self.obs.count_pii(pii_output, "output")
            if presidio_mode != "disabled" and pii_output.has_pii and presidio_mode == "enforce":
                record_presidio_output("scrub", "pii_detected")
                clean_response = await async_redact_output(agent_response)
                result["layers"]["presidio_output"] = {
                    "status": "scrub",
                    "message": f"PII detected in response and scrubbed\nEntities: {', '.join(pii_output.entity_types)}",
                }
                result["response"] = clean_response
                record_tier4("scrub")
                if self.obs is not None:
                    self.obs.security_event(
                        "murdoc.security.pii.scrubbed",
                        layer="presidio_output",
                        decision="scrub",
                        reason="pii_detected",
                        direction="output",
                        entity_types=sorted(pii_output.entity_types),
                        entity_count=pii_output.entity_count,
                    )
            elif presidio_mode != "disabled" and pii_output.has_pii:
                record_presidio_output("flag", "pii_detected")
                result["layers"]["presidio_output"] = {
                    "status": "flag",
                    "message": f"PII detected in response\nEntities: {', '.join(pii_output.entity_types)}",
                }
                result["response"] = agent_response
                record_tier4("flag")
            elif presidio_mode != "disabled":
                record_presidio_output("pass")
                result["layers"]["presidio_output"] = {
                    "status": "pass",
                    "message": "No PII in response",
                }
                result["response"] = agent_response
                record_tier4("pass")

        if (
            cache_key is not None
            and result["layers"].get("opa", {}).get("status") == "pass"
            and result["layers"].get("semantic", {}).get("status") in {"pass", "disabled", "error", "skipped"}
        ):
            self._store_cached_response(cache_key, result)

        self._record_decision(
            preflight,
            normalized_text,
            route_profile,
            tenant_id,
            request_id,
            started,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
            usage=usage,
        )
        return preflight

    async def evaluate_payload(
        self,
        text: str,
        contexts: list[ContextEnvelope] | None = None,
        auth: AuthEnvelope | None = None,
        request_id: str | None = None,
        route_id: str | None = None,
        tenant_id: str = "default",
        app_id: str = "default-app",
        user_id: str = "",
        api_key_fingerprint: str = "",
    ) -> dict[str, Any]:
        started = time.perf_counter()
        contexts = list(contexts or [])
        auth = auth or AuthEnvelope()
        route_profile = self.route_profile(route_id)
        preflight = await self._preflight(
            text,
            contexts,
            auth,
            request_id=request_id,
            route_profile=route_profile,
            tenant_id=tenant_id,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
        )
        self._record_decision(
            preflight,
            text,
            route_profile,
            tenant_id,
            request_id or "",
            started,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
        )
        blocked = bool(preflight.payload.get("blocked", False))
        blocked_by = None
        if blocked:
            layer = preflight.blocked_layer or "runtime"
            if layer == "lakera":
                blocked_by = "Lakera Guard (LLM01 Injection)"
            elif layer == "semantic":
                blocked_by = "NeMo Guardrails (semantic)"
            else:
                blocked_by = f"OPA Policy ({preflight.blocked_reason})"
        return {
            "blocked": blocked,
            "blocked_by": blocked_by,
            "pii_scrubbed": bool(preflight.payload.get("pii_scrubbed", False)),
            "policy_action": preflight.payload.get("layers", {}).get("opa", {}).get("status", "error"),
            "policy_risk": preflight.payload.get("layers", {}).get("opa", {}).get("risk", "unknown"),
            "payload": preflight.payload,
        }

    async def authorize_tool_call(
        self,
        fn_name: str,
        fn_args: dict[str, Any],
        context: dict[str, Any] | None = None,
        request_id: str = "",
        tenant_id: str = "default",
        route_id: str = "mcp-tool",
        app_id: str = "mcp",
        user_id: str = "",
        api_key_fingerprint: str = "",
    ) -> MurdocToolOutcome:
        started = time.perf_counter()
        route_profile = self.route_profile(route_id)
        tool_text = json.dumps(fn_args, sort_keys=True)
        policy_text = f"Tool: {fn_name}\nArguments: {tool_text}"
        contexts: list[ContextEnvelope] = []
        if context:
            contexts.append(
                ContextEnvelope(
                    content=json.dumps(context, sort_keys=True),
                    source="tool_output",
                    trust_level="semi_trusted",
                    can_answer=True,
                    can_influence_goals=False,
                    can_trigger_tools=False,
                )
            )
        outcome = await self._preflight(
            tool_text,
            contexts,
            AuthEnvelope(),
            policy_text=policy_text,
            request_id=request_id,
            route_profile=route_profile,
            tenant_id=tenant_id,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
        )
        self._record_decision(
            outcome,
            tool_text,
            route_profile,
            tenant_id,
            request_id,
            started,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
            tool_name=fn_name,
        )
        return MurdocToolOutcome(
            blocked=bool(outcome.payload.get("blocked", False)),
            blocked_layer=outcome.blocked_layer,
            blocked_reason=outcome.blocked_reason,
            message=outcome.payload.get("message", ""),
            payload=outcome.payload,
        )

    async def scrub_tool_result(self, tool_name: str, result_text: str) -> str:
        _ = tool_name
        presidio_result = await async_scan_output(result_text)
        if presidio_result.has_pii:
            return await async_redact_output(result_text)
        return result_text

    async def inspect_tool_result(
        self,
        tool_name: str,
        result_text: str,
        context: dict[str, Any] | None = None,
        request_id: str = "",
        tenant_id: str = "default",
        route_id: str = "mcp-tool",
        app_id: str = "mcp",
        user_id: str = "",
        api_key_fingerprint: str = "",
    ) -> MurdocToolOutcome:
        started = time.perf_counter()
        route_profile = self.route_profile(route_id)
        contexts = [
            ContextEnvelope(
                content=json.dumps(context or {}, sort_keys=True),
                source="tool_output",
                trust_level="untrusted",
                can_answer=True,
                can_influence_goals=False,
                can_trigger_tools=False,
            )
        ]
        policy_text = f"Tool output from {tool_name}:\n{result_text}"
        outcome = await self._preflight(
            result_text,
            contexts,
            AuthEnvelope(),
            policy_text=policy_text,
            request_id=request_id,
            route_profile=route_profile,
            tenant_id=tenant_id,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
        )
        self._record_decision(
            outcome,
            result_text,
            route_profile,
            tenant_id,
            request_id,
            started,
            app_id=app_id,
            user_id=user_id,
            api_key_fingerprint=api_key_fingerprint,
            tool_name=tool_name,
        )
        outcome.payload["sanitized_text"] = outcome.agent_input or result_text
        return MurdocToolOutcome(
            blocked=bool(outcome.payload.get("blocked", False)),
            blocked_layer=outcome.blocked_layer,
            blocked_reason=outcome.blocked_reason,
            message=outcome.payload.get("message", ""),
            payload=outcome.payload,
        )
