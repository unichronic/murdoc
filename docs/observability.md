# Observability

Murdoc exposes local metrics and can export telemetry through OpenTelemetry.
The bundled local stack is for development and regression work.

## Local Stack

Start the local observability stack:

```bash
./start.sh --observability
```

Or run it directly:

```bash
docker compose -f observability/docker-compose.yml up -d
```

Local endpoints:

```text
Gateway metrics: http://localhost:8000/metrics
Prometheus:      http://localhost:9090
Alertmanager:    http://localhost:9093
Tempo:           http://localhost:3200
Loki:            http://localhost:3100/ready
Grafana:         http://localhost:3000
```

## Signals

The gateway emits:

- HTTP request counts and latency.
- Security layer outcomes.
- Policy decisions and reasons.
- PII entity counts by direction.
- Usage and cost estimates.
- Route/profile metadata.
- Prompt fingerprints, not raw prompts.
- Alertmanager webhook records.

## Safety Rules

Metrics, traces, event logs, audit exports, and decision-ledger records must not
store raw prompts, raw responses, raw API keys, SSNs, emails, or secrets. Use
fingerprints and summaries instead.

## Dashboards

Grafana provisioning lives under `observability/grafana/`. Keep dashboards
operator-oriented: gateway health, block rates, layer latency, policy reasons,
PII redaction counts, route usage, and audit/alert health.
