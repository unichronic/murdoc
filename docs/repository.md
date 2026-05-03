# Repository Guide

The repository is organized around runtime ownership rather than framework
ownership.

```text
murdoc/core/        Shared runtime and request pipeline
murdoc/gateway/     FastAPI gateway, OpenAI endpoint, proxy routes, control API
murdoc/security/    Auth, policy, scanners, guardrails, audit, observability
murdoc/mcp/         MCP adapter, interceptor, and standalone MCP proxy
ui/                 React console
examples/           Runnable examples
tests/python/       Python tests
tests/security/     Go security integration tests
tests/fixtures/     Test policies and target services
tests/tools/        Attack lab and fuzzer helpers
assets/             Documentation assets
observability/      Local metrics, logs, traces, dashboards, alerts
```

## Package Notes

Keep `murdoc/**/__init__.py` files when they define product package boundaries
or public exports. Test and example directories can rely on Python namespace
packages unless a file has real exports.

## Comments And Dev Notes

Prefer clear code over comments. Add comments only when a future maintainer
needs context that is not obvious from the implementation, such as why a
security decision is ordered a certain way or why a fallback is intentionally
fail-open/fail-closed.

## Contributor Checks

Before opening changes:

```bash
python -m pytest -q
cd ui && npm run build
cd ../tests/security && go test ./...
```

Run the attack corpus for runtime, policy, scanner, or target changes.
