# Deployment

Use `./start.sh` for local development and Docker Compose for bundled gateway
and console deployment.

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

## Container

```bash
cp .env.example .env
docker compose --env-file .env up --build
```

The container serves the gateway API, metrics endpoint, and built console on
port `8000`.

Build with optional NeMo dependencies:

```bash
docker build --build-arg PIP_EXTRAS=nemo -t murdoc/gateway:nemo .
```

## State

Docker Compose persists route profiles, gateway routes, and runtime settings in
the `murdoc-state` volume. Decision ledger persistence is opt-in with
`MURDOC_DECISION_LEDGER_FILE` because it writes once per gateway decision.

Production deployments should use platform-managed secrets, ingress TLS,
explicit allowed hosts, secure cookies, persistent state, and telemetry export.
