# Architecture

Murdoc has three gateway modes that map to common agent integration paths.

```text
Agent or client
  -> OpenAI-compatible endpoint, HTTP proxy, or MCP proxy
  -> Murdoc shared security runtime
  -> scanner, redaction, policy, semantic guardrail, and audit layers
  -> upstream model, agent, API, tool, or MCP server
  -> output inspection
  -> response
```

## Gateway Modes

### OpenAI-Compatible LLM Gateway

Point an OpenAI-compatible client at Murdoc and register an upstream provider:

```bash
curl -X PUT http://localhost:8000/api/control-plane/gateway-routes/default-llm \
  -H 'Content-Type: application/json' \
  -d '{"kind":"llm_openai","upstream_url":"https://api.openai.com","profile_id":"default-agent"}'
```

Requests use `/v1/chat/completions`. Murdoc evaluates the message payload
before forwarding it to the upstream model.

### HTTP Tool/API Gateway

Register an internal tool or agent endpoint and call it through `/proxy`:

```bash
curl -X PUT http://localhost:8000/api/control-plane/gateway-routes/support-tools \
  -H 'Content-Type: application/json' \
  -d '{"kind":"http_tool","upstream_url":"http://localhost:8001","profile_id":"tool-write"}'
```

Use this path for tool calls, internal APIs, and agent HTTP endpoints.

### MCP Gateway

Run the standalone MCP proxy against a downstream stdio MCP server:

```bash
export MCP_SERVER_ID=example
export MCP_DOWNSTREAM_COMMAND=python
export MCP_DOWNSTREAM_ARGS="tests/fixtures/targets/fake_mcp_server.py"
python -m murdoc.mcp.proxy_server
```

The proxy filters tool discovery, authorizes tool calls, and inspects textual
tool results before they return to the model context.

## Runtime Boundary

Protocol adapters stay thin. They normalize request content, route metadata,
tenant/app/user identifiers, and auth context into the shared runtime. The
runtime owns the ordered security pipeline and decision ledger writes.

The default local pipeline is deterministic:

1. Ingress normalization.
2. Prompt-attack scanner.
3. Sensitive-data input scan and redaction.
4. OPA-compatible policy decision.
5. Semantic guardrails when enabled and not skipped by lower-risk routing.
6. Backend/tool invocation.
7. Sensitive-data output scan and redaction.
8. Audit-safe decision record.

Local attack-corpus hard blocks are expected to come from the policy layer. Real
Lakera and NeMo behavior must be validated with real-service runs.
