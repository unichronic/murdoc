# Murdoc Documentation

Murdoc is an AI security gateway for model calls, HTTP tools, and MCP traffic.
This documentation is split by the way maintainers and operators usually need
to understand the project.

## Read Next

- [Architecture](architecture.md): gateway modes, request flow, and runtime boundaries.
- [Security](security.md): guardrail layers, auth, RBAC, audit behavior, and hardening.
- [Observability](observability.md): metrics, dashboards, traces, logs, and alerts.
- [Testing](testing.md): unit tests, security tests, attack corpus, and real-service validation.
- [Repository Guide](repository.md): package layout and contributor-facing ownership.
- [Examples](examples.md): runnable examples and MCP demo conventions.
- [Deployment](deployment.md): local, container, and production deployment notes.

## Product Summary

Murdoc sits between agents and the systems they touch. It routes
OpenAI-compatible LLM calls, HTTP tool calls, and MCP sessions through one
shared runtime that can detect prompt injection, scrub sensitive data, enforce
policy, run semantic guardrails, and record audit-safe decision summaries.

The local console is for operators: route configuration, protection profiles,
observability links, attack-lab runs, and enterprise readiness checks. The root
README stays intentionally short; detailed implementation notes live in the
focused docs above.
