# Deployment

Murdoc can run as a deployed gateway on servers, VMs, or private cloud
infrastructure. The basic deployed shape is one gateway container with the built
console served from the same FastAPI process, placed behind normal ingress,
identity, secret, backup, and observability controls.

## Deployed Gateway

Prerequisites:

- A Linux server, VM, or private cloud host with Docker and Compose support.
- A DNS name or internal hostname for the gateway.
- Network access from agent workloads to the Murdoc gateway.
- A strong `MURDOC_ADMIN_TOKEN` for the first local-admin setup path, or an
  enterprise OIDC/identity-proxy configuration.
- A persistent volume or host-mounted storage location for route config and
  audit records.
- TLS termination at ingress or a reverse proxy before exposing Murdoc outside
  a trusted network.

Start from a clean checkout:

```bash
cp .env.example .env
```

Edit `.env` and set at least these deployment defaults:

```bash
MURDOC_ADMIN_TOKEN=<strong-password-or-secret>
MURDOC_AUTH_MODE=local
MURDOC_ALLOWED_HOSTS=<murdoc.internal.example.com>
MURDOC_CONTROL_PLANE_FILE=/app/state/control-plane.json
MURDOC_GATEWAY_ROUTES_FILE=/app/state/gateway-routes.json
MURDOC_RUNTIME_SETTINGS_FILE=/app/state/runtime-settings.json
MURDOC_DECISION_LEDGER_FILE=/app/state/decision-ledger.jsonl
```

For an HTTPS deployment behind ingress, also set:

```bash
MURDOC_SESSION_SECURE=true
MURDOC_SECURITY_HEADERS_ENABLED=true
```

Then run:

```bash
docker compose --env-file .env up --build -d
```

Open through the server hostname or ingress:

```text
Console and gateway: https://<murdoc-host>
Health:              https://<murdoc-host>/healthz
Readiness:           https://<murdoc-host>/readyz
Metrics:             https://<murdoc-host>/metrics
```

Check status and logs:

```bash
docker compose ps
docker compose logs -f gateway
```

Stop the deployment:

```bash
docker compose down
```

State is stored in the `murdoc-state` Docker volume by default. Logs are stored
in the `murdoc-logs` volume. For production operations, mount those paths to
host or platform-managed persistent storage and include them in backup policy.

## Connecting Traffic

Murdoc does not require agents to use a custom SDK. Point existing clients at
one of the gateway paths:

- OpenAI-compatible model calls: `http://<host>:8000/v1/chat/completions`
- HTTP tools and internal APIs: `http://<host>:8000/proxy/{route_id}/...`
- MCP tools: run `murdoc-mcp-proxy` or `python -m murdoc.mcp.proxy_server`
  against the downstream MCP server.

Create routes and profiles from the console or the control-plane API. Keep
provider secrets, upstream credentials, and identity integration in environment
variables or the hosting platform secret manager.

For multi-user deployments, prefer `MURDOC_AUTH_MODE=oidc` or
`MURDOC_AUTH_MODE=proxy` over the single local admin token. Local token auth is
acceptable for first setup, isolated demos, and small internal pilots.

## Local Development

```bash
./start.sh
```

This starts the FastAPI gateway and Vite console. Attack Lab target agents are
started on demand by configured attack runs and torn down after the run.

Useful variants:

```bash
./start.sh --no-ui
./start.sh --agent
./start.sh --observability
./start.sh status
./start.sh stop
```

## Direct Runs

Gateway:

```bash
uvicorn murdoc.gateway.app:app --host 0.0.0.0 --port 8000
```

Console:

```bash
cd ui
npm run dev
```

## Optional Providers

Lakera is optional for local evaluation. Set `LAKERA_API_KEY` to enable the live
prompt-attack scanner. If the key is missing and Lakera is not required, Murdoc
reports the layer as `unavailable` and continues to policy evaluation.

NeMo Guardrails is optional. Build the image with the extra dependency when
that layer is part of the deployment:

```bash
docker build --build-arg PIP_EXTRAS=nemo -t murdoc/gateway:nemo .
```

Leave `OPA_POLICY_URL` empty to use Murdoc's built-in OPA-compatible evaluator.
Set it only when routing policy decisions to an external OPA data API.

## Production Notes

The Compose file is a basic deployment path, not a full production platform.
For production, put Murdoc behind normal enterprise controls:

- TLS and ingress or a reverse proxy.
- Platform-managed secrets.
- Explicit `MURDOC_ALLOWED_HOSTS`.
- `MURDOC_SESSION_SECURE=true` when served over HTTPS.
- OIDC or trusted identity-proxy auth for multi-user environments.
- Persistent state and backed-up decision ledger storage.
- Retention settings that match the deployment's audit policy.
- External metrics, logs, traces, and alert routing.

Use `MURDOC_DEPLOYMENT_PROFILE=production` once those controls are in place so
the console readiness checks reflect production expectations.
