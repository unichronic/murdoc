# Contributing

Keep changes close to the package they affect. Product code should stay separate
from examples, fixtures, and attack-lab helpers.

## Local Checks

```bash
python -m pytest -q
```

```bash
cd tests/security
go test ./...
```

```bash
cd ui
npm run build
```

```bash
python -m py_compile bifrost_gateway/*.py security/*.py mcp_gateway/*.py tests/tools/*.py tests/fixtures/targets/*.py tests/python/*.py
```

## Layout

- Runtime code belongs in `bifrost_gateway/`.
- Policy, guardrail, control-plane, and audit code belongs in `security/`.
- MCP adapter and proxy code belongs in `mcp_gateway/`.
- HTTP adapter and dashboard code belongs in `ui/`.
- User-facing examples belong in `examples/`.
- Python tests belong in `tests/python/`.
- Test targets and policies belong in `tests/fixtures/`.
- Attack-lab helpers belong in `tests/tools/`.

Do not commit generated caches, runtime databases, build output, local logs, or
environment files.
