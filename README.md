# Murdoc

Murdoc is an AI security gateway for agents, tools, and MCP traffic. It gives
security and platform teams one self-hosted control point to inspect requests,
authorize tool calls, redact sensitive data, enforce policy, and audit agent
workflows without rewriting the agent stack.

![Architecture](assets/architecture.svg)

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

Murdoc is open source and designed to run inside the organization's own
environment, where prompt traffic, tool outputs, policies, and audit records can
stay under the team's control.

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

- **Security teams** get a control point for prompt injection, sensitive data,
  tool misuse, policy enforcement, and audit review.
- **Platform teams** get one gateway surface for model calls, HTTP tools, and
  MCP sessions instead of a different security wrapper per framework.
- **Agent developers** keep using standard integration paths: OpenAI-compatible
  clients, HTTP APIs, and MCP-compatible tools.
- **Enterprise maintainers** can run it self-hosted, keep policies close to
  their environment, and regression-test agent behavior with the local attack
  lab.

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

Murdoc keeps the production surface to three plug-and-play modes:

1. **OpenAI-compatible LLM gateway**
   Agents and frameworks point their model client at Murdoc instead of the
   provider directly:

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

2. **HTTP tool/API gateway**
   Agents call internal APIs through registered proxy routes:

   ```bash
   curl -X PUT http://localhost:8000/api/control-plane/gateway-routes/support-tools \
     -H 'Content-Type: application/json' \
     -d '{"kind":"http_tool","upstream_url":"http://localhost:8001","profile_id":"tool-write"}'

   curl -X POST http://localhost:8000/proxy/support-tools/process \
     -H 'Content-Type: application/json' \
     -d '{"text":"Could you open a support ticket?"}'
   ```

3. **MCP gateway**
   MCP-compatible agents connect to the Murdoc MCP server, which proxies to
   the downstream MCP server:

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
murdoc/mcp/            Generic MCP adapter and standalone MCP proxy
ui/                     React dashboard
examples/               Clone-and-run examples
tests/python/           Python tests
tests/security/         Go security integration tests
tests/fixtures/         Test policies and runnable test targets
tests/tools/            Attack lab and fuzzing helpers
assets/                 Images used by the README
observability/          Local metrics, logs, traces, and dashboards
```

## Setup

Install the gateway:

```bash
pip install .
```

Run the gateway API:

```bash
uvicorn murdoc.gateway.app:app --host 0.0.0.0 --port 8000
```

Run the dashboard:

```bash
cd ui
npm install
npm run dev
```

Open `http://localhost:5173`.

The control plane is available in the dashboard and through
`/api/control-plane/*`. It manages gateway upstream routes, route profiles,
audit views, usage summaries, alert intake, non-secret runtime settings, and
local attack-lab settings.

Set `MURDOC_ADMIN_TOKEN` to require `X-Murdoc-Admin-Token` or
`Authorization: Bearer ...` on `/api/control-plane/*`. Leave it empty only for
local development.

Direct local runs keep control-plane state in memory by default. Set
`MURDOC_CONTROL_PLANE_FILE`, `MURDOC_GATEWAY_ROUTES_FILE`, or
`MURDOC_RUNTIME_SETTINGS_FILE` to paths under `data/` when local persistence is
needed outside Docker.

For local development and test-lab dependencies:

```bash
pip install -r requirements.txt
```

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

## Testing

Run Python tests:

```bash
python -m pytest -q
```

Run Go security integration tests:

```bash
cd tests/security
go test ./...
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the repo boundaries and local checks.
