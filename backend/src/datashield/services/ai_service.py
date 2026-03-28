"""AI service — BYOK pattern. Keys are NEVER stored server-side."""
from __future__ import annotations

from typing import Any


async def enhance_detection(
    text: str,
    entities: list[dict[str, Any]],
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """Optionally call Claude to validate/enhance detected entities.

    If *api_key* is ``None`` or empty the original *entities* list is
    returned unchanged (graceful fallback).
    """
    if not api_key:
        return entities

    try:
        import anthropic  # noqa: F811

        client = anthropic.Anthropic(api_key=api_key)
        entity_summary = ", ".join(
            f"{e.get('type', 'UNKNOWN')}:{e.get('text', '')[:30]}" for e in entities[:20]
        )
        message = client.messages.create(
            model="claude-haiku-4-20250414",
            max_tokens=1024,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "You are a PII detection validator. Given the following text and detected entities, "
                        "validate each detection and return a JSON array of objects with keys: "
                        "type, text, confidence (0-1), valid (boolean), reason.\n\n"
                        f"Text (first 500 chars): {text[:500]}\n\n"
                        f"Detected entities: {entity_summary}\n\n"
                        "Return ONLY the JSON array."
                    ),
                }
            ],
        )
        import json

        validated = json.loads(message.content[0].text)
        if isinstance(validated, list):
            # Merge validation back: mark invalid detections
            valid_map = {v.get("text", ""): v for v in validated}
            for entity in entities:
                v = valid_map.get(entity.get("text", ""))
                if v:
                    entity["ai_validated"] = v.get("valid", True)
                    entity["ai_confidence"] = v.get("confidence", entity.get("confidence", 0.9))
                    entity["ai_reason"] = v.get("reason", "")
                else:
                    entity["ai_validated"] = True
        return entities
    except Exception:
        # Graceful fallback — return entities unchanged
        return entities


async def analyze_threat(
    payload: dict[str, Any],
    threat_type: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """AI-enhanced threat analysis.

    Returns an analysis dict. Falls back to a basic stub when no key is
    provided.
    """
    fallback = {
        "threat_type": threat_type,
        "ai_enhanced": False,
        "summary": f"Basic analysis for {threat_type}. Provide an API key for AI-enhanced insights.",
        "risk_level": "unknown",
        "recommendations": [],
    }

    if not api_key:
        return fallback

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-haiku-4-20250414",
            max_tokens=1024,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "You are a cybersecurity analyst specializing in agentic AI threats. "
                        f"Analyze this threat of type '{threat_type}'.\n\n"
                        f"Payload summary: {str(payload)[:800]}\n\n"
                        "Return a JSON object with keys: summary (string), risk_level "
                        "(critical/high/medium/low), recommendations (array of strings), "
                        "indicators (array of strings)."
                    ),
                }
            ],
        )
        import json

        result = json.loads(message.content[0].text)
        result["threat_type"] = threat_type
        result["ai_enhanced"] = True
        return result
    except Exception:
        return fallback
