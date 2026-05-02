"""
Fast policy signal extraction and OPA-compatible decisioning.

The gateway keeps content understanding cheap here: scanners such as Lakera and
Presidio provide heavyweight signals, then this module derives structured intent
signals and evaluates deterministic policy rules. If OPA_POLICY_URL is set, the
same structured input can be sent to an OPA data API endpoint.
"""

from dataclasses import asdict, dataclass, field
import base64
import re
from typing import Any

import httpx

from security.config import (
    OPA_FAIL_CLOSED,
    OPA_POLICY_URL,
    POLICY_BLOCKED_TERMS,
)
from security.control_plane import runtime_settings


EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
PRIVATE_NETWORK_URL_RE = re.compile(
    r"https?://(?:"
    r"localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|"
    r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|"
    r"169\.254(?:\.\d{1,3}){2}"
    r")(?::\d+)?(?:/[^\s'\"<>]*)?",
    re.IGNORECASE,
)
UNSAFE_HTML_RE = re.compile(
    r"<\s*(script|iframe|object|embed|link|meta)\b|on\w+\s*=|javascript:",
    re.IGNORECASE,
)
WRITE_ACTION_RE = re.compile(
    r"\b(update|write|post|send|export|attach|upload|create|delete|drop|wire)\b",
    re.IGNORECASE,
)
EMAIL_ACTION_RE = re.compile(
    r"\bemail\b.*\b(to|all|customer|customers|ssn|ssns|crm|record|records|data)\b",
    re.IGNORECASE,
)
BULK_DATA_RE = re.compile(
    r"\b(all|full|entire|bulk|every|each|dump|export|list)\b.*\b(customer|crm|record|ssn|data|database|vip)\b|"
    r"\b(customer|crm|record|ssn|data|database|vip)\b.*\b(all|full|entire|bulk|every|dump|export|list)\b",
    re.IGNORECASE,
)
SENSITIVE_DOMAIN_RE = re.compile(
    r"\b(ssn|social security|customer records?|vip customer|api key|private key|credential|"
    r"password|payroll|crm|system prompt|internal tools?)\b",
    re.IGNORECASE,
)
SOCIAL_ENGINEERING_RE = re.compile(
    r"\b(urgent|immediately|ceo request|regulatory requirement|do not ask|confidential)\b",
    re.IGNORECASE,
)
RESOURCE_ABUSE_RE = re.compile(
    r"\b(indefinitely|forever|infinite loop|repeat this process|for each customer.*send.*email)\b",
    re.IGNORECASE,
)
PROMPT_INJECTION_RE = re.compile(
    r"\b(ignore previous|disregard all|reveal secrets|jailbreak|developer message|system prompt|dan)\b",
    re.IGNORECASE,
)
READ_ONLY_GOAL_RE = re.compile(
    r"\b(what is|summari[sz]e|explain|look up|point me to|help me|show me an example|policy)\b",
    re.IGNORECASE,
)
WRITE_CHANNEL_RE = re.compile(r"\b(ticket|portal|reply|response|post|write|update)\b", re.IGNORECASE)
DESTRUCTIVE_ACTION_RE = re.compile(r"\b(delete|drop|remove|erase|destroy|wipe)\b", re.IGNORECASE)
EXECUTION_ACTION_RE = re.compile(r"\b(run|execute|shell|script|command|cleanup\.sh|bash)\b", re.IGNORECASE)
FINANCIAL_ACTION_RE = re.compile(r"\b(refund|wire transfer|transfer money|invoice|payment)\b", re.IGNORECASE)
APPROVAL_BYPASS_RE = re.compile(r"\b(do not ask|without approval|no approval|don't ask permission)\b", re.IGNORECASE)
BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
TOOL_CALL_SMUGGLING_RE = re.compile(
    r"(\"tool\"\s*:|\"function\"\s*:|function_call|tool_call|<tool_call>|</tool_call>|"
    r"send_email|query_crm|fetch_url|run_shell|contact_peer_agent)",
    re.IGNORECASE,
)
BROWSER_ACTION_RE = re.compile(r"\b(click|open|visit|navigate|approve|authorize|consent|grant)\b", re.IGNORECASE)
OAUTH_CONSENT_RE = re.compile(
    r"\b(oauth|consent|authorize|authorization|grant access|offline_access|refresh_token|scope)\b",
    re.IGNORECASE,
)
MULTILINGUAL_INSTRUCTION_RE = re.compile(
    r"\b(ignora|ignorer|ignoriere|ignora las instrucciones|exporta|exportar|exportez|envia|enviar|"
    r"registros crm|clientes|dossiers crm|kundendaten)\b",
    re.IGNORECASE,
)


DATA_OBJECT_PATTERNS = {
    "crm_records": re.compile(r"\b(crm|customer records?|customer list|vip customer)\b", re.IGNORECASE),
    "credentials": re.compile(r"\b(credentials?|password|secret|api key|private key)\b", re.IGNORECASE),
    "government_ids": re.compile(r"\b(ssn|social security|passport|driver license)\b", re.IGNORECASE),
    "payroll": re.compile(r"\b(payroll|salary|employee compensation)\b", re.IGNORECASE),
    "database": re.compile(r"\b(database|table|records?)\b", re.IGNORECASE),
    "system_internals": re.compile(r"\b(system prompt|internal tools?)\b", re.IGNORECASE),
}

SOURCE_DEFAULTS = {
    "user": {
        "trust_level": "trusted",
        "can_influence_goals": True,
        "can_trigger_tools": False,
    },
    "memory": {
        "trust_level": "semi_trusted",
        "can_influence_goals": True,
        "can_trigger_tools": False,
    },
    "tool_output": {
        "trust_level": "semi_trusted",
        "can_influence_goals": False,
        "can_trigger_tools": False,
    },
    "retrieved_rag": {
        "trust_level": "untrusted",
        "can_influence_goals": False,
        "can_trigger_tools": False,
    },
    "email": {
        "trust_level": "untrusted",
        "can_influence_goals": False,
        "can_trigger_tools": False,
    },
    "calendar": {
        "trust_level": "untrusted",
        "can_influence_goals": False,
        "can_trigger_tools": False,
    },
    "peer_agent": {
        "trust_level": "semi_trusted",
        "can_influence_goals": False,
        "can_trigger_tools": False,
    },
}

ROLE_DEFAULTS = {
    "anonymous": {
        "allowed_actions": ["read_only"],
        "allowed_data_objects": [],
        "can_access_sensitive_data": False,
        "can_send_external": False,
        "can_execute_code": False,
        "can_mutate_state": False,
    },
    "user": {
        "allowed_actions": ["read_only", "content_write"],
        "allowed_data_objects": [],
        "can_access_sensitive_data": False,
        "can_send_external": False,
        "can_execute_code": False,
        "can_mutate_state": False,
    },
    "analyst": {
        "allowed_actions": ["read_only", "content_write", "data_export"],
        "allowed_data_objects": ["crm_records"],
        "can_access_sensitive_data": False,
        "can_send_external": False,
        "can_execute_code": False,
        "can_mutate_state": False,
    },
    "operator": {
        "allowed_actions": ["read_only", "content_write", "message_send"],
        "allowed_data_objects": ["crm_records"],
        "can_access_sensitive_data": False,
        "can_send_external": False,
        "can_execute_code": False,
        "can_mutate_state": True,
    },
    "admin": {
        "allowed_actions": [
            "read_only",
            "content_write",
            "data_export",
            "external_delivery",
            "message_send",
            "destructive_change",
            "code_execution",
        ],
        "allowed_data_objects": ["crm_records", "credentials", "government_ids", "payroll", "database", "system_internals"],
        "can_access_sensitive_data": True,
        "can_send_external": True,
        "can_execute_code": True,
        "can_mutate_state": True,
    },
}


@dataclass(frozen=True)
class SemanticIntent:
    user_goal: str
    requested_action: str
    tool_intent: str
    data_objects: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    high_impact_action: bool = False
    destructive_action: bool = False
    requires_human_approval: bool = False
    goal_scope_change: bool = False
    approval_bypass_attempt: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ContextEnvelope:
    content: str
    source: str = "user"
    trust_level: str = "trusted"
    can_answer: bool = True
    can_influence_goals: bool = False
    can_trigger_tools: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthEnvelope:
    actor_role: str = "user"
    approved: bool = False
    allowed_actions: list[str] = field(default_factory=list)
    allowed_data_objects: list[str] = field(default_factory=list)
    can_access_sensitive_data: bool = False
    can_send_external: bool = False
    can_execute_code: bool = False
    can_mutate_state: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_context(context: ContextEnvelope) -> ContextEnvelope:
    defaults = SOURCE_DEFAULTS.get(
        context.source,
        {"trust_level": context.trust_level, "can_influence_goals": False, "can_trigger_tools": False},
    )
    return ContextEnvelope(
        content=context.content,
        source=context.source,
        trust_level=context.trust_level or defaults["trust_level"],
        can_answer=context.can_answer,
        can_influence_goals=context.can_influence_goals and defaults["can_influence_goals"],
        can_trigger_tools=context.can_trigger_tools and defaults["can_trigger_tools"],
    )


def normalize_auth(auth: AuthEnvelope | None) -> AuthEnvelope:
    auth = auth or AuthEnvelope()
    defaults = ROLE_DEFAULTS.get(auth.actor_role, ROLE_DEFAULTS["anonymous"])
    return AuthEnvelope(
        actor_role=auth.actor_role,
        approved=auth.approved,
        allowed_actions=auth.allowed_actions or defaults["allowed_actions"],
        allowed_data_objects=auth.allowed_data_objects or defaults["allowed_data_objects"],
        can_access_sensitive_data=auth.can_access_sensitive_data or defaults["can_access_sensitive_data"],
        can_send_external=auth.can_send_external or defaults["can_send_external"],
        can_execute_code=auth.can_execute_code or defaults["can_execute_code"],
        can_mutate_state=auth.can_mutate_state or defaults["can_mutate_state"],
    )


@dataclass(frozen=True)
class PolicyViolation:
    type: str
    reason: str
    layer: str = "opa"


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    allowed: bool
    risk: str
    score: int
    reason: str = "none"
    violations: list[PolicyViolation] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    policy_engine: str = "local"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["violations"] = [asdict(violation) for violation in self.violations]
        return payload


def _pii_summary(presidio_result: Any) -> dict[str, Any]:
    return {
        "has_pii": bool(getattr(presidio_result, "has_pii", False)),
        "entity_count": int(getattr(presidio_result, "entity_count", 0) or 0),
        "entity_types": sorted(getattr(presidio_result, "entity_types", set()) or []),
        "error": getattr(presidio_result, "error", None),
    }


def _lakera_summary(lakera_result: Any, prompt_injection: bool) -> dict[str, Any]:
    return {
        "flagged": bool(getattr(lakera_result, "flagged", False)),
        "request_uuid": getattr(lakera_result, "request_uuid", None),
        "error": getattr(lakera_result, "error", None),
        "prompt_injection": bool(prompt_injection),
    }


def _decoded_fragments(text: str) -> list[str]:
    fragments: list[str] = []
    if "base64" not in text.lower() and "decode" not in text.lower():
        return fragments
    for match in BASE64_BLOB_RE.finditer(text):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if decoded.strip():
            fragments.append(decoded)
    return fragments


def _suspicious_instruction_text(text: str) -> bool:
    fragments = [text] + _decoded_fragments(text)
    return any(
        PROMPT_INJECTION_RE.search(fragment)
        or WRITE_ACTION_RE.search(fragment)
        or EMAIL_ACTION_RE.search(fragment)
        or EXECUTION_ACTION_RE.search(fragment)
        or TOOL_CALL_SMUGGLING_RE.search(fragment)
        or MULTILINGUAL_INSTRUCTION_RE.search(fragment)
        for fragment in fragments
    )


def _contains_encoded_instruction(text: str) -> bool:
    return any(_suspicious_instruction_text(fragment) for fragment in _decoded_fragments(text))


def _context_summary(contexts: list[ContextEnvelope]) -> dict[str, Any]:
    items = []
    poisoned_items = 0
    risky_instructional_items = 0
    influence_candidates = 0
    normalized_sources: dict[str, int] = {}
    for raw_context in contexts:
        context = normalize_context(raw_context)
        content = context.content or ""
        suspicious = _suspicious_instruction_text(content)
        normalized_sources[context.source] = normalized_sources.get(context.source, 0) + 1
        if context.can_influence_goals or context.can_trigger_tools:
            influence_candidates += 1
        if context.trust_level != "trusted" and suspicious and context.source in {
            "email",
            "calendar",
            "memory",
            "retrieved_rag",
            "tool_output",
            "peer_agent",
        }:
            risky_instructional_items += 1
        if context.trust_level != "trusted" and suspicious and (
            context.can_influence_goals or context.can_trigger_tools
        ):
            poisoned_items += 1
        items.append(
            {
                "source": context.source,
                "trust_level": context.trust_level,
                "can_answer": context.can_answer,
                "can_influence_goals": context.can_influence_goals,
                "can_trigger_tools": context.can_trigger_tools,
                "suspicious": suspicious,
            }
        )
    return {
        "count": len(contexts),
        "items": items,
        "source_counts": normalized_sources,
        "risky_instructional_count": risky_instructional_items,
        "untrusted_influence_count": poisoned_items,
        "influence_candidate_count": influence_candidates,
        "poisoned": poisoned_items > 0,
    }


def sanitize_contexts_for_execution(contexts: list[ContextEnvelope]) -> list[ContextEnvelope]:
    sanitized: list[ContextEnvelope] = []
    for raw_context in contexts:
        context = normalize_context(raw_context)
        suspicious = _suspicious_instruction_text(context.content or "")
        if context.trust_level != "trusted" and suspicious:
            sanitized.append(
                ContextEnvelope(
                    content="[UNTRUSTED INSTRUCTIONAL CONTENT REDACTED]",
                    source=context.source,
                    trust_level=context.trust_level,
                    can_answer=context.can_answer,
                    can_influence_goals=False,
                    can_trigger_tools=False,
                )
            )
        else:
            sanitized.append(context)
    return sanitized


def _auth_summary(auth: AuthEnvelope | None) -> dict[str, Any]:
    return normalize_auth(auth).to_dict()


def _extract_destinations(text: str) -> list[str]:
    destinations = []
    destinations.extend(match.group(0) for match in EMAIL_RE.finditer(text))
    destinations.extend(match.group(0) for match in URL_RE.finditer(text))
    return sorted(set(destinations))


def _extract_data_objects(text: str) -> list[str]:
    return sorted(
        name
        for name, pattern in DATA_OBJECT_PATTERNS.items()
        if pattern.search(text)
    )


def extract_semantic_intent(text: str, prompt_injection: bool = False) -> SemanticIntent:
    normalized = text or ""
    decoded_fragments = _decoded_fragments(normalized)
    expanded_text = "\n".join([normalized] + decoded_fragments)
    destinations = _extract_destinations(normalized)
    data_objects = _extract_data_objects(expanded_text)

    if prompt_injection or MULTILINGUAL_INSTRUCTION_RE.search(expanded_text):
        user_goal = "goal_override"
    elif READ_ONLY_GOAL_RE.search(normalized) and not WRITE_ACTION_RE.search(expanded_text):
        user_goal = "information_request"
    elif "reset my password" in normalized.lower():
        user_goal = "account_help"
    elif WRITE_CHANNEL_RE.search(normalized):
        user_goal = "content_update"
    else:
        user_goal = "operational_request"

    read_only_context = (
        user_goal == "information_request"
        and not destinations
        and not WRITE_CHANNEL_RE.search(normalized)
        and not DESTRUCTIVE_ACTION_RE.search(normalized)
        and not EXECUTION_ACTION_RE.search(normalized)
    )

    if read_only_context:
        requested_action = "read_only"
    elif DESTRUCTIVE_ACTION_RE.search(expanded_text):
        requested_action = "destructive_change"
    elif EXECUTION_ACTION_RE.search(expanded_text):
        requested_action = "code_execution"
    elif "export" in expanded_text.lower() or "upload" in expanded_text.lower() or "exporta" in expanded_text.lower():
        requested_action = "data_export"
    elif EMAIL_ACTION_RE.search(expanded_text) or "send" in expanded_text.lower() or "envia" in expanded_text.lower():
        requested_action = "external_delivery" if destinations else "message_send"
    elif WRITE_CHANNEL_RE.search(expanded_text):
        requested_action = "content_write"
    else:
        requested_action = "read_only"

    destructive_action = requested_action == "destructive_change"
    high_impact_action = requested_action in {
        "destructive_change",
        "code_execution",
        "data_export",
        "external_delivery",
        "message_send",
    } or bool(FINANCIAL_ACTION_RE.search(normalized))
    requires_human_approval = high_impact_action and (
        bool(destinations)
        or destructive_action
        or requested_action == "code_execution"
        or bool(FINANCIAL_ACTION_RE.search(normalized))
    )
    approval_bypass_attempt = bool(APPROVAL_BYPASS_RE.search(expanded_text))
    goal_scope_change = (
        prompt_injection
        or (
            user_goal in {"information_request", "account_help"}
            and high_impact_action
        )
    )

    if requested_action in {"data_export", "external_delivery", "message_send"}:
        tool_intent = "communication_or_transfer"
    elif requested_action == "content_write":
        tool_intent = "content_mutation"
    elif requested_action == "code_execution":
        tool_intent = "execution"
    elif destructive_action:
        tool_intent = "destructive_mutation"
    else:
        tool_intent = "read_only"

    return SemanticIntent(
        user_goal=user_goal,
        requested_action=requested_action,
        tool_intent=tool_intent,
        data_objects=data_objects,
        destinations=destinations,
        high_impact_action=high_impact_action,
        destructive_action=destructive_action,
        requires_human_approval=requires_human_approval,
        goal_scope_change=goal_scope_change,
        approval_bypass_attempt=approval_bypass_attempt,
    )


def extract_policy_signals(
    text: str,
    lakera_result: Any = None,
    presidio_result: Any = None,
    prompt_injection: bool = False,
    contexts: list[ContextEnvelope] | None = None,
    auth: AuthEnvelope | None = None,
) -> dict[str, Any]:
    normalized = text or ""
    lower_text = normalized.lower()
    expanded_text = "\n".join([normalized] + _decoded_fragments(normalized))
    blocked_terms = [term for term in POLICY_BLOCKED_TERMS if term in lower_text]
    destinations = _extract_destinations(normalized)
    emails = [dest for dest in destinations if "@" in dest]
    urls = [dest for dest in destinations if dest.startswith("http")]
    has_external_destination = bool(destinations)
    has_prompt_injection = bool(prompt_injection or PROMPT_INJECTION_RE.search(expanded_text))
    intent = extract_semantic_intent(normalized, prompt_injection=has_prompt_injection)
    contexts = contexts or []

    return {
        "text_length": len(normalized),
        "prompt_injection": has_prompt_injection,
        "blocked_terms": blocked_terms,
        "external_destination": has_external_destination,
        "external_email_count": len(emails),
        "external_url_count": len(urls),
        "private_network_destination": bool(PRIVATE_NETWORK_URL_RE.search(normalized)),
        "unsafe_html": bool(UNSAFE_HTML_RE.search(normalized)),
        "write_action": bool(WRITE_ACTION_RE.search(expanded_text) or EMAIL_ACTION_RE.search(expanded_text)),
        "bulk_data_request": bool(BULK_DATA_RE.search(expanded_text)),
        "sensitive_domain": bool(SENSITIVE_DOMAIN_RE.search(expanded_text)),
        "social_engineering": bool(SOCIAL_ENGINEERING_RE.search(normalized)),
        "resource_abuse": bool(RESOURCE_ABUSE_RE.search(normalized) or len(normalized) > 8000),
        "encoded_instruction": _contains_encoded_instruction(normalized),
        "tool_call_smuggling": bool(TOOL_CALL_SMUGGLING_RE.search(normalized)),
        "browser_action": bool(BROWSER_ACTION_RE.search(normalized) and destinations),
        "oauth_consent": bool(OAUTH_CONSENT_RE.search(normalized) and destinations),
        "multilingual_instruction": bool(MULTILINGUAL_INSTRUCTION_RE.search(normalized)),
        "intent": intent.to_dict(),
        "context": _context_summary(contexts),
        "auth": _auth_summary(auth),
        "lakera": _lakera_summary(lakera_result, has_prompt_injection),
        "presidio": _pii_summary(presidio_result),
    }


def build_policy_input(
    text: str,
    lakera_result: Any = None,
    presidio_result: Any = None,
    prompt_injection: bool = False,
    contexts: list[ContextEnvelope] | None = None,
    auth: AuthEnvelope | None = None,
) -> dict[str, Any]:
    return {
        "signals": extract_policy_signals(
            text,
            lakera_result=lakera_result,
            presidio_result=presidio_result,
            prompt_injection=prompt_injection,
            contexts=contexts,
            auth=auth,
        )
    }


def _risk(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def evaluate_local(policy_input: dict[str, Any]) -> PolicyDecision:
    signals = policy_input["signals"]
    intent = signals["intent"]
    context = signals["context"]
    auth = signals["auth"]
    violations: list[PolicyViolation] = []
    score = 0

    def add(kind: str, reason: str, points: int) -> None:
        nonlocal score
        violations.append(PolicyViolation(kind, reason))
        score = max(score, points)

    privileged_sensitive_transfer = (
        auth["can_send_external"]
        and auth["can_access_sensitive_data"]
        and auth["approved"]
    )

    if signals["prompt_injection"]:
        add("prompt_injection", "prompt_injection", 95)
    if context["poisoned"]:
        add("memory_context_poisoning", "untrusted_context_influence", 91)
    if context["risky_instructional_count"]:
        add("untrusted_context", "instructional_untrusted_context", 89)
    if intent["goal_scope_change"]:
        add("agent_goal_hijack", "goal_scope_change", 88)
    if intent["high_impact_action"] and intent["requested_action"] not in auth["allowed_actions"]:
        add("identity_privilege_abuse", "action_not_permitted", 89)
    if intent["requested_action"] == "external_delivery" and not auth["can_send_external"]:
        add("identity_privilege_abuse", "external_delivery_not_permitted", 90)
    if intent["requested_action"] == "code_execution" and not auth["can_execute_code"]:
        add("identity_privilege_abuse", "code_execution_not_permitted", 92)
    if intent["destructive_action"] and not auth["can_mutate_state"]:
        add("identity_privilege_abuse", "destructive_change_not_permitted", 90)
    if (
        any(obj in {"credentials", "government_ids", "payroll", "system_internals"} for obj in intent["data_objects"])
        and intent["high_impact_action"]
        and not auth["can_access_sensitive_data"]
    ):
        add("identity_privilege_abuse", "sensitive_data_not_permitted", 90)
    if (
        intent["data_objects"]
        and intent["high_impact_action"]
        and any(obj not in auth["allowed_data_objects"] for obj in intent["data_objects"])
        and auth["actor_role"] != "admin"
    ):
        add("identity_privilege_abuse", "data_scope_not_permitted", 88)
    if intent["requires_human_approval"] and not auth["approved"]:
        add("identity_privilege_abuse", "approval_required", 86)
    if signals["blocked_terms"]:
        add("blocked_term", "policy_violation", 85)
    if signals["resource_abuse"]:
        add("resource_abuse", "resource_abuse", 90)
    if signals["encoded_instruction"]:
        add("instruction_smuggling", "encoded_instruction_smuggling", 89)
    if signals["tool_call_smuggling"] and (signals["external_destination"] or signals["sensitive_domain"] or signals["bulk_data_request"]):
        add("tool_misuse", "tool_call_smuggling", 88)
    if signals["browser_action"] and (signals["external_destination"] or signals["sensitive_domain"]):
        add("tool_misuse", "browser_action_hijack", 86)
    if signals["oauth_consent"]:
        add("identity_privilege_abuse", "oauth_consent_abuse", 87)
    if signals["multilingual_instruction"] and (intent["high_impact_action"] or signals["sensitive_domain"]):
        add("instruction_smuggling", "multilingual_instruction_smuggling", 86)
    if signals["private_network_destination"]:
        add("tool_misuse", "private_network_fetch", 88)
    if intent["approval_bypass_attempt"] and intent["requires_human_approval"]:
        add("tool_misuse", "approval_bypass_attempt", 87)
    if intent["requested_action"] == "code_execution":
        add("tool_misuse", "unexpected_code_execution", 92)
    if intent["destructive_action"] and intent["requires_human_approval"]:
        add("tool_misuse", "destructive_tool_misuse", 90)
    if signals["unsafe_html"] and signals["write_action"]:
        add("unsafe_output_handling", "unsafe_html_write", 85)
    if (
        signals["external_destination"]
        and signals["write_action"]
        and (
            signals["bulk_data_request"]
            or signals["sensitive_domain"]
            or signals["presidio"]["has_pii"]
        )
        and not privileged_sensitive_transfer
    ):
        add("data_exfiltration", "external_sensitive_transfer", 90)
    if signals["social_engineering"] and signals["external_destination"] and signals["sensitive_domain"]:
        add("social_engineering", "coerced_sensitive_transfer", 80)

    if violations:
        return PolicyDecision(
            action="block",
            allowed=False,
            risk=_risk(score),
            score=score,
            reason=violations[0].reason,
            violations=violations,
            signals=signals,
        )

    if signals["presidio"]["has_pii"]:
        return PolicyDecision(
            action="scrub",
            allowed=True,
            risk="medium",
            score=35,
            reason="pii_redaction_required",
            signals=signals,
        )

    return PolicyDecision(
        action="allow",
        allowed=True,
        risk="low",
        score=0,
        signals=signals,
    )


def _decision_from_opa_result(result: dict[str, Any], signals: dict[str, Any]) -> PolicyDecision:
    raw = result.get("result", result)
    action = raw.get("action") or ("allow" if raw.get("allow", False) else "block")
    violations = [
        PolicyViolation(
            type=item.get("type", "policy_violation"),
            reason=item.get("reason", "policy_violation"),
            layer=item.get("layer", "opa"),
        )
        for item in raw.get("violations", [])
        if isinstance(item, dict)
    ]
    allowed = bool(raw.get("allowed", action in ("allow", "scrub")))
    score = int(raw.get("score", 0) or 0)
    return PolicyDecision(
        action=action,
        allowed=allowed,
        risk=raw.get("risk", _risk(score)),
        score=score,
        reason=raw.get("reason", violations[0].reason if violations else "none"),
        violations=violations,
        signals=signals,
        policy_engine="opa",
    )


async def evaluate_policy(
    text: str,
    lakera_result: Any = None,
    presidio_result: Any = None,
    prompt_injection: bool = False,
    contexts: list[ContextEnvelope] | None = None,
    auth: AuthEnvelope | None = None,
) -> PolicyDecision:
    settings = runtime_settings.get_settings()
    policy_input = build_policy_input(
        text,
        lakera_result=lakera_result,
        presidio_result=presidio_result,
        prompt_injection=prompt_injection,
        contexts=contexts,
        auth=auth,
    )
    if not OPA_POLICY_URL:
        return evaluate_local(policy_input)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                OPA_POLICY_URL,
                json={"input": policy_input},
                timeout=settings.opa_timeout_seconds,
            )
            response.raise_for_status()
            return _decision_from_opa_result(response.json(), policy_input["signals"])
    except Exception:
        if settings.opa_fail_closed:
            return PolicyDecision(
                action="block",
                allowed=False,
                risk="high",
                score=80,
                reason="opa_unavailable",
                violations=[PolicyViolation("policy_engine", "opa_unavailable")],
                signals=policy_input["signals"],
                policy_engine="opa",
            )
        return evaluate_local(policy_input)
