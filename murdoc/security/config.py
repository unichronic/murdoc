"""Environment-backed gateway configuration."""

import os
import ipaddress
import secrets
from dotenv import load_dotenv

load_dotenv()


def _csv_env(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _cidr_env(name: str, default: str) -> list:
    networks = []
    for item in _csv_env(name, default):
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks

# Prompt-attack scanner.
LAKERA_API_KEY = os.getenv("LAKERA_API_KEY", "")
LAKERA_API_URL = os.getenv("LAKERA_API_URL", "https://api.lakera.ai")
LAKERA_CONFIDENCE_THRESHOLD = float(os.getenv("LAKERA_CONFIDENCE_THRESHOLD", "0.8"))
LAKERA_REQUIRED = os.getenv("LAKERA_REQUIRED", "false").lower() == "true"
LAKERA_PROJECT_ID = os.getenv("LAKERA_PROJECT_ID", "").strip()
LAKERA_BREAKDOWN = os.getenv("LAKERA_BREAKDOWN", "false").lower() == "true"

# Sensitive data scanner.
PRESIDIO_SCORE_THRESHOLD = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.3"))
PRESIDIO_ENTITIES = _csv_env(
    "PRESIDIO_ENTITIES",
    (
        "CREDIT_CARD,EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,IP_ADDRESS,IBAN_CODE,"
        "CRYPTO,US_PASSPORT,US_DRIVER_LICENSE,US_BANK_NUMBER"
    ),
)
PRESIDIO_REDACT_PLACEHOLDER = "<REDACTED:{entity_type}>"

# Semantic guardrails.
NEMO_GUARDRAILS_ENABLED = os.getenv("NEMO_GUARDRAILS_ENABLED", "false").lower() == "true"
NEMO_GUARDRAILS_REQUIRED = os.getenv("NEMO_GUARDRAILS_REQUIRED", "false").lower() == "true"
NEMO_GUARDRAILS_ENFORCE = os.getenv("NEMO_GUARDRAILS_ENFORCE", "false").lower() == "true"
NEMO_GUARDRAILS_MAX_CONCURRENCY = int(os.getenv("NEMO_GUARDRAILS_MAX_CONCURRENCY", "1"))
NEMO_GUARDRAILS_MAX_RETRIES = int(os.getenv("NEMO_GUARDRAILS_MAX_RETRIES", "2"))
NEMO_GUARDRAILS_RETRY_BACKOFF_SECONDS = float(os.getenv("NEMO_GUARDRAILS_RETRY_BACKOFF_SECONDS", "2.0"))
NEMO_GUARDRAILS_SKIP_LOW_RISK_READS = os.getenv("NEMO_GUARDRAILS_SKIP_LOW_RISK_READS", "true").lower() == "true"
NEMO_GUARDRAILS_CONFIG_PATH = os.getenv("NEMO_GUARDRAILS_CONFIG_PATH", "").strip()
NEMO_GUARDRAILS_MAIN_MODEL = os.getenv("NEMO_GUARDRAILS_MAIN_MODEL", "meta/llama-3.3-70b-instruct").strip()
NEMO_GUARDRAILS_CONTENT_SAFETY_MODEL = os.getenv(
    "NEMO_GUARDRAILS_CONTENT_SAFETY_MODEL",
    "nvidia/llama-3.1-nemoguard-8b-content-safety",
).strip()

# Gateway.
GATEWAY_HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))
MURDOC_ADMIN_TOKEN = os.getenv("MURDOC_ADMIN_TOKEN", "").strip()
MURDOC_AUTH_MODE = os.getenv("MURDOC_AUTH_MODE", "local").strip().lower()
MURDOC_SESSION_SECURE = os.getenv("MURDOC_SESSION_SECURE", "false").lower() == "true"
MURDOC_AUTH_PROXY_USER_HEADER = os.getenv("MURDOC_AUTH_PROXY_USER_HEADER", "X-Forwarded-User").strip()
MURDOC_AUTH_PROXY_EMAIL_HEADER = os.getenv("MURDOC_AUTH_PROXY_EMAIL_HEADER", "X-Forwarded-Email").strip()
MURDOC_AUTH_PROXY_GROUPS_HEADER = os.getenv("MURDOC_AUTH_PROXY_GROUPS_HEADER", "X-Forwarded-Groups").strip()
MURDOC_AUTH_PROXY_TRUSTED_IPS = _cidr_env("MURDOC_AUTH_PROXY_TRUSTED_IPS", "")
MURDOC_OIDC_ISSUER = os.getenv("MURDOC_OIDC_ISSUER", "").strip()
MURDOC_OIDC_AUDIENCE = os.getenv("MURDOC_OIDC_AUDIENCE", "").strip()
MURDOC_OIDC_JWKS_URL = os.getenv("MURDOC_OIDC_JWKS_URL", "").strip()
MURDOC_OIDC_GROUPS_CLAIM = os.getenv("MURDOC_OIDC_GROUPS_CLAIM", "groups").strip()
MURDOC_RBAC_ADMIN_GROUPS = _csv_env("MURDOC_RBAC_ADMIN_GROUPS", "murdoc-admins")
MURDOC_RBAC_OPERATOR_GROUPS = _csv_env("MURDOC_RBAC_OPERATOR_GROUPS", "murdoc-operators")
MURDOC_RBAC_VIEWER_GROUPS = _csv_env("MURDOC_RBAC_VIEWER_GROUPS", "murdoc-viewers")
MURDOC_AUDIT_RETENTION_DAYS = int(os.getenv("MURDOC_AUDIT_RETENTION_DAYS", "90"))
MURDOC_DECISION_LEDGER_MAX_RECORDS = int(os.getenv("MURDOC_DECISION_LEDGER_MAX_RECORDS", "1000"))
MURDOC_DEPLOYMENT_PROFILE = os.getenv("MURDOC_DEPLOYMENT_PROFILE", "development").strip().lower()
MURDOC_REQUIRE_PERSISTENCE_FOR_PRODUCTION = os.getenv("MURDOC_REQUIRE_PERSISTENCE_FOR_PRODUCTION", "true").lower() == "true"
MURDOC_SECURITY_HEADERS_ENABLED = os.getenv("MURDOC_SECURITY_HEADERS_ENABLED", "true").lower() == "true"
MURDOC_ALLOWED_HOSTS = _csv_env("MURDOC_ALLOWED_HOSTS", "*")
MURDOC_CONTROL_PLANE_FILE = os.getenv("MURDOC_CONTROL_PLANE_FILE", "").strip()
MURDOC_GATEWAY_ROUTES_FILE = os.getenv("MURDOC_GATEWAY_ROUTES_FILE", "").strip()
MURDOC_RUNTIME_SETTINGS_FILE = os.getenv("MURDOC_RUNTIME_SETTINGS_FILE", "").strip()
MURDOC_DECISION_LEDGER_FILE = os.getenv("MURDOC_DECISION_LEDGER_FILE", "").strip()
MURDOC_READ_CACHE_ENABLED = os.getenv("MURDOC_READ_CACHE_ENABLED", "true").lower() == "true"
MURDOC_READ_CACHE_MAX_ITEMS = int(os.getenv("MURDOC_READ_CACHE_MAX_ITEMS", "256"))
MURDOC_READ_CACHE_TTL_SECONDS = int(os.getenv("MURDOC_READ_CACHE_TTL_SECONDS", "300"))
AGENT_BACKEND_URL = os.getenv("AGENT_BACKEND_URL", "").strip()
AGENT_MEMORY_CONTEXT_URL = os.getenv("AGENT_MEMORY_CONTEXT_URL", "").strip()
AGENT_BACKEND_TIMEOUT = float(os.getenv("AGENT_BACKEND_TIMEOUT", "10"))
POLICY_BLOCKED_TERMS = [
    term.strip().lower()
    for term in os.getenv(
        "POLICY_BLOCKED_TERMS",
        "delete database,drop table,wire transfer,exfiltrate,private key",
    ).split(",")
    if term.strip()
]
OPA_POLICY_URL = os.getenv("OPA_POLICY_URL", "").strip()
OPA_TIMEOUT_SECONDS = float(os.getenv("OPA_TIMEOUT_SECONDS", "1.0"))
OPA_FAIL_CLOSED = os.getenv("OPA_FAIL_CLOSED", "false").lower() == "true"


def constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
