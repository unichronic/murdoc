"""Sensitive data scanner and redactor."""

import logging
import re
import anyio
from dataclasses import dataclass, field
from typing import List, Optional

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from murdoc.security.config import (
    PRESIDIO_SCORE_THRESHOLD,
    PRESIDIO_ENTITIES,
    PRESIDIO_REDACT_PLACEHOLDER,
)

logger = logging.getLogger(__name__)


@dataclass
class DetectedEntity:
    entity_type: str
    text: str
    start: int
    end: int
    score: float


@dataclass
class PresidioResult:
    has_pii: bool = False
    entities: List[DetectedEntity] = field(default_factory=list)
    entity_count: int = 0
    entity_types: set = field(default_factory=set)
    original_text: str = ""
    error: Optional[str] = None


def _build_custom_secret_recognizers() -> List[PatternRecognizer]:
    """Build Murdoc-specific recognizers that Presidio does not ship by default."""
    recognizers = []

    ssn_recognizer = PatternRecognizer(
        supported_entity="US_SSN",
        name="USSSNRecognizer",
        patterns=[
            Pattern(
                name="ssn_dash_format",
                regex=r"\b\d{3}-\d{2}-\d{4}\b",
                score=0.95,
            ),
        ],
        context=["ssn", "social security", "taxpayer"],
    )
    recognizers.append(ssn_recognizer)

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

    connection_string_recognizer = PatternRecognizer(
        supported_entity="CONNECTION_STRING",
        name="ConnectionStringRecognizer",
        patterns=[
            Pattern(
                name="db_connection_uri",
                regex=r"\b(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://\S+:\S+@\S+",
                score=0.9,
            ),
        ],
    )
    recognizers.append(connection_string_recognizer)

    return recognizers


def _initialize_analyzer() -> AnalyzerEngine:
    analyzer = AnalyzerEngine()

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
    return AnonymizerEngine()


# Dev note: engine instances are initialized lazily to keep test collection and
# local startup fast. Presidio engines are read-only after construction here.
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


def scan_output(text: str) -> PresidioResult:
    """Scan text for PII and secret material."""
    result = PresidioResult(original_text=text)

    if not text or not text.strip():
        return result

    try:
        analyzer = _get_analyzer()

        entities_to_detect = list(PRESIDIO_ENTITIES) + [
            "API_KEY",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "PRIVATE_KEY",
            "PASSWORD",
            "CONNECTION_STRING",
        ]

        analyzer_results = analyzer.analyze(
            text=text,
            entities=entities_to_detect,
            language="en",
            score_threshold=PRESIDIO_SCORE_THRESHOLD,
        )

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

    except Exception as exc:
        logger.error(f"Presidio scan failed: {exc}")
        result.error = f"Scan failed: {exc}"

    return result


def redact_output(text: str) -> str:
    """Redact detected PII and secrets from text."""
    if not text or not text.strip():
        return text

    try:
        analyzer = _get_analyzer()
        anonymizer = _get_anonymizer()

        entities_to_detect = list(PRESIDIO_ENTITIES) + [
            "API_KEY",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "PRIVATE_KEY",
            "PASSWORD",
            "CONNECTION_STRING",
        ]

        analyzer_results = analyzer.analyze(
            text=text,
            entities=entities_to_detect,
            language="en",
            score_threshold=PRESIDIO_SCORE_THRESHOLD,
        )

        if not analyzer_results:
            return text

        operators = {
            "DEFAULT": OperatorConfig(
                "replace",
                {"new_value": PRESIDIO_REDACT_PLACEHOLDER}
            ),
        }

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
        # Dev note: the gateway logs the failure and leaves policy layers to
        # decide whether fail-open is acceptable for the active route.
        logger.error(f"Presidio redaction failed: {e}")
        return text


def has_sensitive_data(text: str) -> bool:
    """Return True when scan_output finds any PII or secret material."""
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
        return f"[Presidio] Scan error: {result.error}"

    if result.has_pii:
        entity_summary = ", ".join(
            f"{etype}({sum(1 for e in result.entities if e.entity_type == etype)})"
            for etype in result.entity_types
        )
        return (
            f"[Presidio] DETECTED {result.entity_count} entities - "
            f"{entity_summary}"
        )

    return "[Presidio] Clean - No PII/secrets detected"

async def async_scan_output(text: str) -> PresidioResult:
    """Async wrapper for the CPU-bound scan_output function."""
    if not text:
        return PresidioResult(original_text=text)
    return await anyio.to_thread.run_sync(scan_output, text)

async def async_redact_output(text: str) -> str:
    """Async wrapper for the CPU-bound redact_output function."""
    if not text:
        return text
    return await anyio.to_thread.run_sync(redact_output, text)

async def async_has_sensitive_data(text: str) -> bool:
    """Async wrapper for the CPU-bound has_sensitive_data function."""
    if not text:
        return False
    return await anyio.to_thread.run_sync(has_sensitive_data, text)


async def warmup_presidio() -> None:
    """Warm the analyzer and anonymizer on realistic no-op and redact paths."""
    samples = [
        "Warmup policy summary request.",
        "Contact hr@example.com about payroll.",
    ]
    for sample in samples:
        await async_scan_output(sample)
        await async_redact_output(sample)
