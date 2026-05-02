"""Lazy exports for the gateway security package."""


def __getattr__(name):
    """Load optional security modules only when they are used."""
    if name == "scan_prompt":
        from security.lakera_guard import scan_prompt
        return scan_prompt
    if name == "scan_output":
        from security.presidio_scanner import scan_output
        return scan_output
    if name == "redact_output":
        from security.presidio_scanner import redact_output
        return redact_output
    if name == "scan_semantics":
        from security.semantic_guardrails import scan_semantics
        return scan_semantics
    raise AttributeError(f"module 'security' has no attribute {name!r}")


__all__ = ["scan_prompt", "scan_semantics", "scan_output", "redact_output"]
