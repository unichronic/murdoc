"""
Layer 4: Presidio — PII & Secret Leak Detection
=================================================

This module integrates Microsoft Presidio to detect and redact Personally
Identifiable Information (PII) and secrets from LLM agent OUTPUT before
it reaches the end user.

Detects: credit cards, emails, phone numbers, SSNs, API keys, tokens,
         AWS keys, private keys, IP addresses, IBANs, crypto wallets, etc.

Presidio Docs: https://microsoft.github.io/presidio/

Usage:
    from security.presidio_analyzer import scan_output, redact_output

    result = scan_output("Contact john@example.com or call 555-0123")
    if result.has_pii:
        clean_text = redact_output(result.original_text)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from security.config import (
    PRESIDIO_SCORE_THRESHOLD,
    PRESIDIO_ENTITIES,
    PRESIDIO_REDACT_PLACEHOLDER,
)

# Configure logging for the Presidio module
logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class DetectedEntity:
    """
    A single PII/secret entity detected in the text.

    Attributes:
        entity_type : Type of entity (e.g., "CREDIT_CARD", "EMAIL_ADDRESS")
        text        : The actual detected text
        start       : Start character index in original text
        end         : End character index in original text
        score       : Confidence score of the detection (0.0 to 1.0)
    """
    entity_type: str
    text: str
    start: int
    end: int
    score: float


@dataclass
class PresidioResult:
    """
    Result from a Presidio output scan.

    Attributes:
        has_pii        : True if any PII/secret entities were detected
        entities       : List of detected PII/secret entities
        entity_count   : Total number of entities detected
        entity_types   : Set of unique entity types found
        original_text  : The original text that was scanned
        error          : Error message if the scan failed
    """
    has_pii: bool = False
    entities: List[DetectedEntity] = field(default_factory=list)
    entity_count: int = 0
    entity_types: set = field(default_factory=set)
    original_text: str = ""
    error: Optional[str] = None


# =============================================================================
# Custom Recognizers for Secrets/Keys
# =============================================================================

def _build_custom_secret_recognizers() -> List[PatternRecognizer]:
    """
    Build custom Presidio pattern recognizers for detecting secrets,
    API keys, tokens, and other sensitive data that the default
    Presidio recognizers don't cover.

    Returns:
        List of custom PatternRecognizer instances.
    """

    recognizers = []

    # --- 1. CVV Code ---
    cvv_recognizer = PatternRecognizer(
        supported_entity="CVV",
        name="CVVRecognizer",
        patterns=[
            Pattern(
                name="cvv",
                regex=r"\bCVV:?\s*\d{3,4}\b",
                score=0.95,
            ),
        ],
        context=["cvv", "security code", "card"],
    )
    recognizers.append(cvv_recognizer)

    # --- 2. 2FA Secret / TOTP ---
    totp_recognizer = PatternRecognizer(
        supported_entity="2FA_SECRET",
        name="TOTPRecognizer",
        patterns=[
            Pattern(
                name="totp_secret",
                regex=r"\b2FA Secret:?\s*[A-Z2-7]{16,}\b",
                score=0.95,
            ),
        ],
        context=["2fa", "totp", "secret", "authenticator"],
    )
    recognizers.append(totp_recognizer)

    # --- 3. Password Hash ---
    password_hash_recognizer = PatternRecognizer(
        supported_entity="PASSWORD_HASH",
        name="PasswordHashRecognizer",
        patterns=[
            Pattern(
                name="bcrypt_hash",
                regex=r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53,}",
                score=0.95,
            ),
        ],
        context=["password", "hash", "bcrypt"],
    )
    recognizers.append(password_hash_recognizer)

    # --- 4. Security Questions ---
    security_question_recognizer = PatternRecognizer(
        supported_entity="SECURITY_ANSWER",
        name="SecurityQuestionRecognizer",
        patterns=[
            Pattern(
                name="security_answer",
                regex=r"Security Question \d+[^:]*:\s*([^\n]+)",
                score=0.9,
            ),
        ],
        context=["security question", "mother's maiden", "first pet", "first car"],
    )
    recognizers.append(security_question_recognizer)

    # --- 5. Medical Conditions ---
    medical_recognizer = PatternRecognizer(
        supported_entity="MEDICAL_CONDITION",
        name="MedicalConditionRecognizer",
        patterns=[
            Pattern(
                name="medical_condition",
                regex=r"Medical Conditions?:?\s*([^\n]+)",
                score=0.9,
            ),
            Pattern(
                name="prescription",
                regex=r"Prescription Medications?:?\s*([^\n]+)",
                score=0.9,
            ),
        ],
        context=["medical", "prescription", "medication", "condition", "diagnosis"],
    )
    recognizers.append(medical_recognizer)

    # --- 6. Generic API Key Detector ---
    api_key_recognizer = PatternRecognizer(
        supported_entity="API_KEY",
        name="APIKeyRecognizer",
        patterns=[
            Pattern(
                name="prefixed_key",
                regex=r"\b(?:sk|pk|api|key|token|bearer|secret|access)[_\-]?[A-Za-z0-9]{20,}\b",
                score=0.85,
            ),
            Pattern(
                name="hex_token",
                regex=r"\b[a-fA-F0-9]{32,}\b",
                score=0.6,
            ),
        ],
        context=["key", "token", "secret", "api", "password", "credential", "auth"],
    )
    recognizers.append(api_key_recognizer)

    # --- 7. AWS Access Key Detector ---
    aws_key_recognizer = PatternRecognizer(
        supported_entity="AWS_ACCESS_KEY",
        name="AWSAccessKeyRecognizer",
        patterns=[
            Pattern(
                name="aws_access_key",
                regex=r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
                score=0.95,
            ),
        ],
        context=["aws", "access", "key", "credential", "iam"],
    )
    recognizers.append(aws_key_recognizer)

    # --- 3. AWS Secret Key Detector ---
    aws_secret_recognizer = PatternRecognizer(
        supported_entity="AWS_SECRET_KEY",
        name="AWSSecretKeyRecognizer",
        patterns=[
            Pattern(
                name="aws_secret_key",
                regex=r"\b[A-Za-z0-9/+=]{40}\b",
                score=0.7,
            ),
        ],
        context=["aws", "secret", "key", "credential"],
    )
    recognizers.append(aws_secret_recognizer)

    # --- 4. Private Key Detector ---
    # Detects PEM-encoded private keys
    private_key_recognizer = PatternRecognizer(
        supported_entity="PRIVATE_KEY",
        name="PrivateKeyRecognizer",
        patterns=[
            Pattern(
                name="pem_private_key",
                regex=r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                score=0.99,
            ),
            Pattern(
                name="pem_ec_key",
                regex=r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
                score=0.99,
            ),
        ],
    )
    recognizers.append(private_key_recognizer)

    # --- 5. Generic Password Detector ---
    # Detects password patterns like "password: xxx" or "passwd=xxx"
    # TODO: Expand patterns for your application's specific password formats.
    password_recognizer = PatternRecognizer(
        supported_entity="PASSWORD",
        name="PasswordRecognizer",
        patterns=[
            Pattern(
                name="password_assignment",
                regex=r"(?:password|passwd|pwd|pass)\s*[:=]\s*\S+",
                score=0.8,
            ),
        ],
    )
    recognizers.append(password_recognizer)

    # --- 6. Connection String Detector ---
    # Detects database connection strings and URIs with credentials
    connection_string_recognizer = PatternRecognizer(
        supported_entity="CONNECTION_STRING",
        name="ConnectionStringRecognizer",
        patterns=[
            # Database connection URIs (postgres://, mysql://, mongodb://, redis://)
            Pattern(
                name="db_connection_uri",
                regex=r"\b(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://\S+:\S+@\S+",
                score=0.9,
            ),
        ],
    )
    recognizers.append(connection_string_recognizer)

    # TODO: Add more custom recognizers here, for example:
    # - GitHub/GitLab personal access tokens (ghp_, glpat-)
    # - Slack tokens (xoxb-, xoxp-)
    # - Stripe keys (sk_live_, pk_live_)
    # - JWT tokens (eyJ...)

    return recognizers


# =============================================================================
# Engine Initialization
# =============================================================================

# TODO: Consider lazy initialization if startup time is a concern.
#       The AnalyzerEngine loads NLP models which can take a few seconds.

def _initialize_analyzer() -> AnalyzerEngine:
    """
    Initialize the Presidio AnalyzerEngine with default + custom recognizers.

    Returns:
        Configured AnalyzerEngine instance.
    """
    analyzer = AnalyzerEngine()

    # Register custom secret recognizers
    custom_recognizers = _build_custom_secret_recognizers()
    for recognizer in custom_recognizers:
        analyzer.registry.add_recognizer(recognizer)
        logger.debug(f"Registered custom recognizer: {recognizer.name}")

    logger.info(
        f"Presidio AnalyzerEngine initialized with "
        f"{len(custom_recognizers)} custom recognizers."
    )

    return analyzer


def _initialize_anonymizer() -> AnonymizerEngine:
    """
    Initialize the Presidio AnonymizerEngine for redacting detected PII.

    Returns:
        Configured AnonymizerEngine instance.
    """
    return AnonymizerEngine()


# --- Module-level engine instances (initialized once on import) ---
# TODO: Consider thread-safety implications if running in a multi-threaded server.
#       Presidio engines are generally thread-safe for read operations.
_analyzer_engine: Optional[AnalyzerEngine] = None
_anonymizer_engine: Optional[AnonymizerEngine] = None


def _get_analyzer() -> AnalyzerEngine:
    """Get or lazily initialize the analyzer engine."""
    global _analyzer_engine
    if _analyzer_engine is None:
        _analyzer_engine = _initialize_analyzer()
    return _analyzer_engine


def _get_anonymizer() -> AnonymizerEngine:
    """Get or lazily initialize the anonymizer engine."""
    global _anonymizer_engine
    if _anonymizer_engine is None:
        _anonymizer_engine = _initialize_anonymizer()
    return _anonymizer_engine


# =============================================================================
# Core Scanning Function
# =============================================================================

def scan_output(text: str) -> PresidioResult:
    """
    Scan LLM agent output for PII and secrets using Presidio.

    Runs the Presidio AnalyzerEngine against the output text to detect
    entities like credit card numbers, emails, API keys, etc.

    Args:
        text: The LLM agent's output text to scan.

    Returns:
        PresidioResult with has_pii=True if any entities were detected.

    Example:
        >>> result = scan_output("Contact support at admin@company.com")
        >>> result.has_pii
        True
        >>> result.entities[0].entity_type
        'EMAIL_ADDRESS'
    """

    result = PresidioResult(original_text=text)

    if not text or not text.strip():
        return result

    try:
        analyzer = _get_analyzer()

        # --- Build the list of entities to detect ---
        # Combine default Presidio entities with our custom secret types
        entities_to_detect = list(PRESIDIO_ENTITIES) + [
            "API_KEY",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "PRIVATE_KEY",
            "PASSWORD",
            "CONNECTION_STRING",
        ]

        # --- Run the Presidio analyzer ---
        # TODO: Support multiple languages by making `language` configurable.
        analyzer_results = analyzer.analyze(
            text=text,
            entities=entities_to_detect,
            language="en",
            score_threshold=PRESIDIO_SCORE_THRESHOLD,
        )

        # --- Convert Presidio results to our data model ---
        for entity in analyzer_results:
            detected = DetectedEntity(
                entity_type=entity.entity_type,
                text=text[entity.start:entity.end],
                start=entity.start,
                end=entity.end,
                score=entity.score,
            )
            result.entities.append(detected)
            result.entity_types.add(entity.entity_type)

        result.entity_count = len(result.entities)
        result.has_pii = result.entity_count > 0

        if result.has_pii:
            logger.warning(
                f"Presidio detected {result.entity_count} PII/secret entities: "
                f"{result.entity_types}"
            )

    except Exception as e:
        # TODO: Add more specific exception handling:
        #       - NLP model loading errors
        #       - Memory errors for very large texts
        #       - Invalid entity type errors
        logger.error(f"Presidio scan failed: {e}")
        result.error = f"Scan failed: {e}"

    return result


# =============================================================================
# Redaction Function
# =============================================================================

def redact_output(text: str) -> str:
    """
    Redact detected PII/secrets from the agent output text.

    Uses the Presidio AnonymizerEngine to replace detected entities
    with placeholder tags (e.g., "<REDACTED:EMAIL_ADDRESS>").

    Args:
        text: The LLM agent's output text to redact.

    Returns:
        The text with all detected PII/secrets replaced by redaction placeholders.

    Example:
        >>> redact_output("Email me at john@example.com")
        'Email me at <REDACTED:EMAIL_ADDRESS>'
    """

    if not text or not text.strip():
        return text

    try:
        analyzer = _get_analyzer()
        anonymizer = _get_anonymizer()

        # --- Build entity list (same as scan_output) ---
        entities_to_detect = list(PRESIDIO_ENTITIES) + [
            "API_KEY",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "PRIVATE_KEY",
            "PASSWORD",
            "CONNECTION_STRING",
        ]

        # --- Detect entities ---
        analyzer_results = analyzer.analyze(
            text=text,
            entities=entities_to_detect,
            language="en",
            score_threshold=PRESIDIO_SCORE_THRESHOLD,
        )

        if not analyzer_results:
            return text

        # --- Build operator config for redaction ---
        # TODO: Customize redaction operators per entity type if needed.
        #       For example, you might want to:
        #       - Hash emails instead of redacting
        #       - Mask credit cards (show last 4 digits)
        #       - Encrypt certain fields for later recovery
        #
        #       Example:
        #       operators = {
        #           "CREDIT_CARD": OperatorConfig("mask", {"chars_to_mask": 12,
        #                                                   "masking_char": "*",
        #                                                   "from_end": False}),
        #           "EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"}),
        #       }
        operators = {
            "DEFAULT": OperatorConfig(
                "replace",
                {"new_value": PRESIDIO_REDACT_PLACEHOLDER}
            ),
        }

        # --- Apply redaction ---
        anonymized = anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators,
        )

        logger.info(
            f"Presidio redacted {len(analyzer_results)} entities from output."
        )

        return anonymized.text

    except Exception as e:
        # TODO: Decide on fallback behavior when redaction fails:
        #       1. Return original text (risky — may leak PII)
        #       2. Return empty string (safe but unhelpful)
        #       3. Return generic error message
        #       Currently: returns original text with warning.
        logger.error(f"Presidio redaction failed: {e}")
        return text


# =============================================================================
# Utility Functions
# =============================================================================

def has_sensitive_data(text: str) -> bool:
    """
    Simple boolean helper — returns True if the output contains PII/secrets.

    Convenience wrapper around scan_output() for quick yes/no checks.

    Args:
        text: The output text to check.

    Returns:
        True if any PII or secret entities were detected.

    Example:
        >>> if has_sensitive_data(agent_response):
        ...     agent_response = redact_output(agent_response)
    """
    result = scan_output(text)
    return result.has_pii


def get_scan_summary(result: PresidioResult) -> str:
    """
    Generate a human-readable summary of a Presidio scan result.

    Useful for logging and debugging.

    Args:
        result: A PresidioResult from scan_output().

    Returns:
        A formatted summary string.
    """
    if result.error:
        return f"[Presidio] ⚠️  Scan error: {result.error}"

    if result.has_pii:
        entity_summary = ", ".join(
            f"{etype}({sum(1 for e in result.entities if e.entity_type == etype)})"
            for etype in result.entity_types
        )
        return (
            f"[Presidio] 🚨 DETECTED {result.entity_count} entities — "
            f"{entity_summary}"
        )

    return "[Presidio] ✅ Clean — No PII/secrets detected"
