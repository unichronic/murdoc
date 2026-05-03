# Testing

Murdoc has normal developer tests and product-facing attack-lab tests. Use both
when changing runtime, policy, routing, auth, or control-plane behavior.

## Developer Tests

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

## Attack Corpus

Run the deterministic local corpus:

```bash
python tests/tools/attack_lab.py --profile extended --mode gateway --iterations 1 --concurrency 4 --json
```

Run gateway-vs-raw comparison with stateful scenarios:

```bash
python tests/tools/attack_lab.py --profile extended --mode compare --iterations 1 --concurrency 4 --include-stateful --json
```

The deterministic local corpus intentionally validates local policy behavior.
It should report Lakera as `unavailable` unless a real Lakera key is configured.
Layer attribution is part of the fuzzer summary:

```json
{
  "attribution_errors": 0,
  "block_layers": {
    "opa": 96
  }
}
```

## Real-Service Validation

Use real-service mode when validating Lakera, NeMo, or HTTP OPA integration:

```bash
export LAKERA_API_KEY=...
export LAKERA_REQUIRED=true
export NEMO_GUARDRAILS_ENABLED=true
export NEMO_GUARDRAILS_REQUIRED=true
python tests/tools/attack_lab.py --profile baseline --mode gateway --real-services --json
```

Real-service validation fails fast if configured layers silently fall back to
disabled or local behavior.

## Test Folders

- `tests/python/`: Python unit, API, integration, attack-lab, and MCP tests.
- `tests/security/`: Go security integration tests for middleware-like layers.
- `tests/fixtures/`: policies and runnable vulnerable target services.
- `tests/tools/`: attack corpus, attack lab, fuzzer, and lab environment helpers.
