"""
Security Package - AI Security Middleware
==========================================

This package provides agent-agnostic security layers for protecting
LLM agents from prompt injection attacks and PII/secret leakage.

Layers provided:
    - Layer 3 (Lakera Guard): ML-based prompt injection detection on INPUT
    - Layer 4 (Presidio): PII/secret leak detection and redaction on OUTPUT

Usage:
    from security.lakera_guard import scan_prompt
    from security.presidio_scanner import scan_output, redact_output

Note: Imports are lazy to avoid import errors when optional dependencies
      (e.g., spaCy for Presidio) are not installed or incompatible.
"""


def __getattr__(name):
    """
    Lazy import handler — only loads modules when their exports are accessed.
    This prevents spaCy/Presidio import failures from blocking Lakera usage.
    """
    if name == "scan_prompt":
        from security.lakera_guard import scan_prompt
        return scan_prompt
    if name == "scan_output":
        from security.presidio_scanner import scan_output
        return scan_output
    if name == "redact_output":
        from security.presidio_scanner import redact_output
        return redact_output
    raise AttributeError(f"module 'security' has no attribute {name!r}")


__all__ = ["scan_prompt", "scan_output", "redact_output"]
