# Security

Murdoc is designed to make the gateway the enforcement boundary instead of
burying security decisions inside prompts or per-agent wrappers.

## Guardrail Layers

- Prompt scanner: Lakera Guard integration for prompt-injection signals.
- Sensitive-data scanner: Presidio-based PII and secret detection/redaction.
- Policy engine: local OPA-compatible evaluator or HTTP OPA endpoint.
- Semantic guardrails: optional NeMo Guardrails layer for semantic checks.
- MCP security: tool allow/block lists, read-only mode, call authorization, and
  tool-result inspection.

In deterministic local testing, Lakera is normally unavailable and reported as
`unavailable`; this is not a clean pass. OPA owns hard block decisions for the
local corpus unless real services are explicitly enabled.

## Control Plane Auth

Murdoc supports three operator access modes:

- `local`: console password with `MURDOC_ADMIN_TOKEN`.
- `oidc`: bearer-token validation against OIDC issuer JWKS.
- `proxy`: trusted identity headers from an ingress, OAuth2/OIDC proxy, or SAML
  identity proxy.

For proxy mode, set `MURDOC_AUTH_PROXY_TRUSTED_IPS` to the proxy or ingress
CIDR. Without that, identity headers are easy to spoof if clients can reach
Murdoc directly.

RBAC roles:

- Viewer: read control-plane state and audit summaries.
- Operator: update routes/profiles/runtime settings and run attack-lab checks.
- Admin: reserved for ownership and emergency access.

Configure group mappings with `MURDOC_RBAC_ADMIN_GROUPS`,
`MURDOC_RBAC_OPERATOR_GROUPS`, and `MURDOC_RBAC_VIEWER_GROUPS`.

## Audit Behavior

Murdoc records decision summaries without storing raw prompts, raw responses,
raw API keys, SSNs, emails, or secrets. Records include request id, route,
tenant/app/user metadata, layer outcomes, policy versions, prompt fingerprint,
usage estimates, and cost metadata.

Set `MURDOC_DECISION_LEDGER_FILE` for persisted JSONL audit records. The ledger
reloads persisted records on restart, prunes records outside
`MURDOC_AUDIT_RETENTION_DAYS`, and compacts the file after pruning.

## Production Hardening

For production deployments:

- Set `MURDOC_DEPLOYMENT_PROFILE=production`.
- Require operator auth and RBAC.
- Terminate TLS at a trusted ingress.
- Set `MURDOC_SESSION_SECURE=true`.
- Set `MURDOC_ALLOWED_HOSTS` to public gateway hostnames.
- Store secrets in the platform secret manager.
- Persist route/profile/runtime state.
- Persist the decision ledger when audit retention is required.
- Export metrics/traces/logs to the organization observability stack.

The console Overview tab surfaces readiness checks for access control,
configuration persistence, audit retention, deployment hardening, and
observability.
