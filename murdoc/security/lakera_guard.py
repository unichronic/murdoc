"""Prompt-attack scanner integration."""

import httpx
import logging
from dataclasses import dataclass
from typing import Optional

from murdoc.security.config import (
    LAKERA_API_KEY,
    LAKERA_API_URL,
    LAKERA_REQUIRED,
    LAKERA_PROJECT_ID,
)
from murdoc.security.control_plane import runtime_settings

logger = logging.getLogger(__name__)


@dataclass
class LakeraResult:
    """Result from the prompt-attack scanner."""
    flagged: bool = False
    request_uuid: Optional[str] = None
    raw_response: Optional[dict] = None
    error: Optional[str] = None
    confidence: Optional[float] = None


async def scan_prompt(text: str, request_id: Optional[str] = None) -> LakeraResult:
    """Scan user input for prompt injection and jailbreak attempts."""
    settings = runtime_settings.get_settings()

    if not LAKERA_API_KEY:
        level = logger.error if settings.lakera_required else logger.warning
        level(
            "LAKERA_API_KEY is not set. Lakera Guard is unavailable."
        )
        return LakeraResult(
            flagged=False,
            error="LAKERA_API_KEY not configured"
        )

    endpoint = f"{LAKERA_API_URL}/v2/guard"

    headers = {
        "Authorization": f"Bearer {LAKERA_API_KEY}",
        "Content-Type": "application/json",
    }

    messages = [{"role": "user", "content": text}]
    payload = {"messages": messages}
    if LAKERA_PROJECT_ID:
        payload["project_id"] = LAKERA_PROJECT_ID
    if settings.lakera_breakdown:
        payload["breakdown"] = True
    if request_id:
        payload["metadata"] = {"request_id": request_id}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=10.0,
            )
            response.raise_for_status()

    except httpx.TimeoutException:
        logger.error("Lakera Guard API request timed out.")
        result = LakeraResult(flagged=False, error="API request timed out")

    except httpx.ConnectError:
        logger.error("Failed to connect to Lakera Guard API.")
        result = LakeraResult(flagged=False, error="Connection failed")

    except httpx.HTTPStatusError as e:
        logger.error(f"Lakera Guard API HTTP error: {e}")
        result = LakeraResult(flagged=False, error=f"HTTP error: {e}")

    except httpx.RequestError as e:
        logger.error(f"Lakera Guard API request failed: {e}")
        result = LakeraResult(flagged=False, error=f"Request failed: {e}")
    else:
        try:
            data = response.json()
            result = _parse_lakera_response(data)
        except ValueError:
            logger.error("Lakera Guard API returned invalid JSON.")
            result = LakeraResult(flagged=False, error="Invalid JSON response")

    return result


def _parse_lakera_response(data: dict) -> LakeraResult:
    """Parse the scanner response into our small result type."""
    settings = runtime_settings.get_settings()

    result = LakeraResult(raw_response=data)

    try:
        metadata = data.get("metadata", {})
        result.confidence = metadata.get("confidence") or data.get("confidence")
        
        if result.confidence is not None:
            result.flagged = result.confidence >= settings.lakera_confidence_threshold
        else:
            result.flagged = data.get("flagged", False)

        result.request_uuid = metadata.get("request_uuid")

    except (KeyError, TypeError) as e:
        logger.error(f"Failed to parse Lakera Guard response: {e}")
        result.error = f"Parse error: {e}"

    return result


async def is_prompt_injection(text: str) -> bool:
    """Return True when the input is flagged."""
    result = await scan_prompt(text)
    return result.flagged


def get_scan_summary(result: LakeraResult) -> str:
    """Short text summary for logs."""
    if result.error:
        return f"[Lakera] Scan error: {result.error}"

    if result.flagged:
        return (
            f"[Lakera] BLOCKED - "
            f"Request ID: {result.request_uuid or 'unknown'}"
        )

    return f"[Lakera] Clean - Request ID: {result.request_uuid or 'N/A'}"
