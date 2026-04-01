"""
Security Configuration
======================

Centralized configuration for all security layers.
Loads settings from environment variables with sensible defaults.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Layer 3: Lakera Guard
LAKERA_API_KEY = os.getenv("LAKERA_API_KEY", "")
LAKERA_API_URL = os.getenv("LAKERA_API_URL", "https://api.lakera.ai")
LAKERA_CONFIDENCE_THRESHOLD = float(os.getenv("LAKERA_CONFIDENCE_THRESHOLD", "0.8"))
LAKERA_FALLBACK_PATTERNS = [
    pattern.strip().lower()
    for pattern in os.getenv(
        "LAKERA_FALLBACK_PATTERNS",
        "ignore previous instructions,disregard all previous,reveal secrets,"
        "system prompt,jailbreak,developer message,exfiltrate",
    ).split(",")
    if pattern.strip()
]

# Layer 4: Presidio
PRESIDIO_SCORE_THRESHOLD = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.3"))
PRESIDIO_ENTITIES = [
    "CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN",
    "IP_ADDRESS", "IBAN_CODE", "CRYPTO", "PERSON", "US_PASSPORT",
    "US_DRIVER_LICENSE", "LOCATION", "DATE_TIME", "NRP", "URL",
    "US_BANK_NUMBER", "AU_ABN", "AU_ACN", "AU_TFN", "AU_MEDICARE",
]
PRESIDIO_REDACT_PLACEHOLDER = "<REDACTED:{entity_type}>"

# Gateway
GATEWAY_HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))
AGENT_BACKEND_URL = os.getenv("AGENT_BACKEND_URL", "").strip()
AGENT_BACKEND_TIMEOUT = float(os.getenv("AGENT_BACKEND_TIMEOUT", "10"))
POLICY_BLOCKED_TERMS = [
    term.strip().lower()
    for term in os.getenv(
        "POLICY_BLOCKED_TERMS",
        "delete database,drop table,wire transfer,exfiltrate,private key",
    ).split(",")
    if term.strip()
]
