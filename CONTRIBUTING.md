# Contributing

Keep changes close to the package they affect. Product code should stay separate
from examples, fixtures, and attack-lab helpers.

## Local Checks

```bash
pip install -r requirements.txt
```

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
python -m py_compile murdoc/core/*.py murdoc/gateway/*.py murdoc/mcp/*.py murdoc/security/*.py tests/tools/*.py tests/fixtures/targets/*.py tests/python/*.py
```

## Layout

- Runtime code belongs in `murdoc/core/`.
- Policy, guardrail, control-plane, and audit code belongs in `murdoc/security/`.
- MCP adapter and proxy code belongs in `murdoc/mcp/`.
- HTTP gateway code belongs in `murdoc/gateway/`.
- Dashboard code belongs in `ui/`.
- User-facing examples belong in `examples/`.
- Python tests belong in `tests/python/`.
- Test targets and policies belong in `tests/fixtures/`.
- Attack-lab helpers belong in `tests/tools/`.

Do not commit generated caches, runtime databases, build output, local logs, or
environment files.

Keep `/api/process`, `/v1/chat/completions`, `/proxy/*`, and MCP adapter changes
separate from control-plane hardening so reliability and latency-sensitive agent
paths stay easy to review.
