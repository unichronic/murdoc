# Murdoc Guide

This guide contains the detailed product, integration, operations, observability,
and testing notes that are intentionally kept out of the root README.

## What It Does

- Protects OpenAI-compatible LLM calls before they reach model providers.
- Protects HTTP tool/API calls before agents can touch internal services.
- Protects MCP sessions before tool output reaches the model context window.
- Runs all three modes through the same policy, guardrail, redaction, and audit runtime.
- Filters available MCP tools before a model or agent can select them.
- Authorizes every tool/API call before it reaches the downstream server.
- Inspects tool output before it is returned to the model.
- Records decisions without storing raw prompts, raw secrets, or raw responses.
- Includes a local attack lab for regression testing gateway behavior.
- Ships a small dashboard, control plane, and local observability stack for development.

## Why Murdoc

Most AI gateways focus on model routing, provider abstraction, caching, retries,
and cost controls. Those are useful, but agent risk is different: agents read
untrusted context, call tools, touch internal APIs, and carry tool output back
into the model context window.

Murdoc is built for that security boundary. It gives teams a gateway-layer
place to enforce policy before an agent acts, inspect tool output before the
model sees it, redact sensitive data before it leaves the runtime, and preserve
audit evidence without turning every agent codebase into a custom security
project.

## Where It Fits

- Security teams get a control point for prompt injection, sensitive data, tool
  misuse, policy enforcement, and audit review.
- Platform teams get one gateway surface for model calls, HTTP tools, and MCP
  sessions instead of a different security wrapper per framework.
- Agent developers keep using standard integration paths: OpenAI-compatible
  clients, HTTP APIs, and MCP-compatible tools.
- Enterprise maintainers can run it self-hosted, keep policies close to their
  environment, and regression-test agent behavior with the local attack lab.

## How It Works

```text
Client or agent
  -> OpenAI-compatible endpoint, HTTP proxy, or MCP proxy
  -> shared security runtime
  -> policy and data checks
  -> upstream model, agent, API, tool, or MCP server
  -> output inspection
  -> response
```

The runtime receives a normalized request envelope with actor, tenant, route,
content, context, and tool metadata. Adapters stay protocol-specific; policy and
decision logic stays shared.

## Agent Integration Modes

Murdoc keeps the production surface to three plug-and-play modes.

### OpenAI-Compatible LLM Gateway

Agents and frameworks point their model client at Murdoc instead of the provider
directly:

```bash
curl -X PUT http://localhost:8000/api/control-plane/gateway-routes/default-llm \
  -H 'Content-Type: application/json' \
  -d '{"kind":"llm_openai","upstream_url":"https://api.openai.com","profile_id":"default-agent"}'

curl http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $OPENAI_API_KEY' \
  -d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"Hello"}]}'
```

You can also set `MURDOC_DEFAULT_LLM_UPSTREAM_URL=https://api.openai.com`
before startup to register `default-llm` automatically.

### HTTP Tool/API Gateway

Agents call internal APIs through registered proxy routes:

```bash
curl -X PUT http://localhost:8000/api/control-plane/gateway-routes/support-tools \
  -H 'Content-Type: application/json' \
  -d '{"kind":"http_tool","upstream_url":"http://localhost:8001","profile_id":"tool-write"}'

curl -X POST http://localhost:8000/proxy/support-tools/process \
  -H 'Content-Type: application/json' \
  -d '{"text":"Could you open a support ticket?"}'
```

### MCP Gateway

MCP-compatible agents connect to the Murdoc MCP server, which proxies to the
downstream MCP server:

```bash
export MCP_SERVER_ID=example
export MCP_DOWNSTREAM_COMMAND=python
export MCP_DOWNSTREAM_ARGS="tests/fixtures/targets/fake_mcp_server.py"
python -m murdoc.mcp.proxy_server
```

## Repository Layout

```text
murdoc/core/        Shared runtime
murdoc/gateway/     HTTP gateway, OpenAI-compatible endpoint, and control-plane API
murdoc/security/    Policy, guardrail, control-plane, and audit modules
murdoc/mcp/         Generic MCP adapter and standalone MCP proxy
ui/                 React dashboard
examples/           Clone-and-run examples
tests/python/       Python tests
tests/security/     Go security integration tests
tests/fixtures/     Test policies and runnable test targets
tests/tools/        Attack lab and fuzzing helpers
assets/             Images used by documentation
observability/      Local metrics, logs, traces, and dashboards
```

## Control Plane And Console

The control plane manages gateway upstream routes, route profiles, audit views,
usage summaries, alert intake, non-secret runtime settings, and local
attack-lab settings.

Set `MURDOC_ADMIN_TOKEN` to require console sign-in and admin authorization on
control-plane APIs. Leave it empty only for local development. Direct local runs
keep control-plane state in memory by default. Set `MURDOC_CONTROL_PLANE_FILE`,
`MURDOC_GATEWAY_ROUTES_FILE`, or `MURDOC_RUNTIME_SETTINGS_FILE` to paths under
`data/` when local persistence is needed outside Docker.

## Enterprise Hardening

Murdoc supports three access patterns for production operators:

- Local console password: set `MURDOC_AUTH_MODE=local` and `MURDOC_ADMIN_TOKEN`
  for a single administrative credential.
- Native OIDC API access: set `MURDOC_AUTH_MODE=oidc`,
  `MURDOC_OIDC_ISSUER`, and `MURDOC_OIDC_AUDIENCE`. Murdoc validates bearer
  tokens against the issuer JWKS and maps groups to RBAC roles.
- Identity proxy access: set `MURDOC_AUTH_MODE=proxy` when an ingress,
  OAuth2/OIDC proxy, or SAML identity proxy authenticates users before traffic
  reaches Murdoc and forwards trusted identity headers. Set
  `MURDOC_AUTH_PROXY_TRUSTED_IPS` to the proxy or ingress CIDR so identity
  headers cannot be spoofed by direct clients.

RBAC uses three roles. Viewers can read control-plane state and audit summaries.
Operators can update routes, profiles, runtime settings, and run the attack
lab. Admins inherit operator permissions and should be reserved for emergency
or ownership tasks. Configure group mappings with
`MURDOC_RBAC_ADMIN_GROUPS`, `MURDOC_RBAC_OPERATOR_GROUPS`, and
`MURDOC_RBAC_VIEWER_GROUPS`.

For production deployments, set `MURDOC_DEPLOYMENT_PROFILE=production`, enable
TLS at ingress, store secrets in the platform secret manager, enable secure
cookies with `MURDOC_SESSION_SECURE=true`, set `MURDOC_ALLOWED_HOSTS` to the
public gateway hostnames, mount persistent state files, and set
`MURDOC_DECISION_LEDGER_FILE` with an audit retention window. The decision
ledger reloads persisted JSONL records on restart, prunes records outside
`MURDOC_AUDIT_RETENTION_DAYS`, and compacts the file after retention pruning.
The console Overview tab reports whether access control, configuration storage,
audit retention, deployment hardening, and observability are ready.

Native SAML is normally handled by an identity proxy in front of Murdoc. That
keeps assertion parsing, IdP metadata rotation, and session lifecycle in the
enterprise identity layer while Murdoc receives already-authenticated
principals and applies RBAC locally.

## Container Deployment

Build and run the gateway with the bundled UI:

```bash
cp .env.example .env
docker compose --env-file .env up --build
```

The container serves:

```text
Gateway API and UI: http://localhost:8000
Metrics:            http://localhost:8000/metrics
Control plane:      http://localhost:8000/api/control-plane/*
```

Build with optional NeMo Guardrails dependencies when that layer is part of the
deployment:

```bash
docker build --build-arg PIP_EXTRAS=nemo -t murdoc/gateway:nemo .
```

Secrets and provider endpoints stay in environment variables. Non-secret runtime
settings such as fail-closed behavior, guardrail modes, and thresholds are
managed through the control plane.

The container persists route profiles, gateway routes, and runtime settings in
the `murdoc-state` volume. Decision ledger file persistence is opt-in with
`MURDOC_DECISION_LEDGER_FILE` because it writes once per gateway decision.

## MCP Proxy

Run the standalone MCP proxy against any stdio MCP server:

```bash
export MCP_SERVER_ID=example
export MCP_DOWNSTREAM_COMMAND=python
export MCP_DOWNSTREAM_ARGS="tests/fixtures/targets/fake_mcp_server.py"
export MCP_ENFORCE_TOOL_ALLOWLIST=true
export MCP_ALLOWED_TOOLS=example:safe_search

python -m murdoc.mcp.proxy_server
```

The proxy exposes an MCP server upstream and keeps a downstream MCP session open.
Discovery responses are filtered, tool calls are authorized, and textual results
are inspected before they are returned.

## Notion MCP Example

The Notion example lives under `examples/mcp/notion`. Configure provider keys in
that directory, install its dependencies, then run the demo client:

```bash
cd examples/mcp/notion
cp .env.example .env
pip install -r requirements.txt
python client.py "What pages are in my workspace?"
```

To run the Notion MCP server through Murdoc from the repo root:

```bash
export MCP_SERVER_ID=notion
export MCP_DOWNSTREAM_COMMAND=npx
export MCP_DOWNSTREAM_ARGS="-y @notionhq/notion-mcp-server"
export NOTION_TOKEN=ntn_...

python -m murdoc.mcp.proxy_server
```

Tool filtering is controlled with `MCP_ENFORCE_TOOL_ALLOWLIST`,
`MCP_ALLOWED_TOOLS`, `MCP_BLOCKED_TOOLS`, and `MCP_READ_ONLY_MODE`.

## Observability

The local observability stack lives under `observability/` and includes
OpenTelemetry Collector, Tempo, Prometheus, Alertmanager, Loki, Promtail, and
Grafana. Start it with:

```bash
./start.sh --observability
```

Or run it directly:

```bash
docker compose -f observability/docker-compose.yml up -d
```

Useful local endpoints:

```text
Gateway metrics: http://localhost:8000/metrics
Prometheus:      http://localhost:9090
Alertmanager:    http://localhost:9093
Tempo:           http://localhost:3200
Loki:            http://localhost:3100/ready
Grafana:         http://localhost:3000
```

The gateway emits request counts, latency, guardrail layer outcomes, usage
estimates, route metadata, and prompt fingerprints. It does not write raw
prompts, raw responses, raw API keys, SSNs, emails, or secrets to metrics,
traces, event logs, audit exports, or the decision ledger.

## Testing

Murdoc has two product-facing testing actions in the local Attack Lab UI:

- Quick corpus scan: the `/api/fuzz` smoke test for fast policy checks against the active corpus.
- Configured run: the `/api/control-plane/test-run` harness for saved corpus, target, mode, iteration, and concurrency settings.

Developer checks are still run from the command line.

Run Python tests:

```bash
python -m pytest -q
```

Run Go security integration tests:

```bash
cd tests/security
go test ./...
```

Run selected Go security tests:

```bash
cd tests/security
go test -run TestOPAMiddleware -v
go test -run TestLakeraMiddleware -v
go test -run TestPresidioMiddleware -v
```

Build the UI:

```bash
cd ui
npm run build
```

Run the local attack lab:

```bash
python tests/tools/attack_lab.py --mode compare --profile extended --iterations 3 --concurrency 6 --include-stateful
```
