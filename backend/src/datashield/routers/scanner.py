"""Scan, protect (tokenize/redact/pseudonymize), restore, batch, validate endpoints."""
from __future__ import annotations
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from datashield.database import get_db
from datashield.services.detection_engine import detect, scan_text, get_entity_registry, get_detection_stats
from datashield.services.token_vault import tokenize, restore, create_session, ObfuscationMode, tokenize_simple

router = APIRouter(prefix="/api", tags=["scanner"])

# Entity type → metadata
_ENTITY_META = {
    "SSN": {"category": "PII", "regulatory_basis": "GDPR Art.87, CCPA, HIPAA", "risk_level": "CRITICAL", "default_action": "REDACT"},
    "EMAIL": {"category": "PII", "regulatory_basis": "GDPR Art.4(1), CCPA 1798.140(o)", "risk_level": "HIGH", "default_action": "TOKENIZE"},
    "PHONE": {"category": "PII", "regulatory_basis": "GDPR Art.4(1), CCPA", "risk_level": "HIGH", "default_action": "TOKENIZE"},
    "CREDIT_CARD": {"category": "PCI", "regulatory_basis": "PCI DSS Req.3, GDPR Art.4(1)", "risk_level": "CRITICAL", "default_action": "REDACT"},
    "IP_ADDRESS": {"category": "PII", "regulatory_basis": "GDPR Rec.30, CCPA 1798.140(o)", "risk_level": "MEDIUM", "default_action": "MASK"},
    "PERSON_NAME": {"category": "PII", "regulatory_basis": "GDPR Art.4(1), HIPAA 164.514", "risk_level": "HIGH", "default_action": "TOKENIZE"},
    "IBAN": {"category": "FINANCIAL", "regulatory_basis": "PCI DSS, GDPR Art.4(1), SOX", "risk_level": "CRITICAL", "default_action": "REDACT"},
    "API_KEY": {"category": "IP_CODE", "regulatory_basis": "SOX Section 302, Internal Policy", "risk_level": "CRITICAL", "default_action": "REDACT"},
    "DATE": {"category": "PHI", "regulatory_basis": "HIPAA 164.514(b)(2)(i)", "risk_level": "MEDIUM", "default_action": "GENERALIZE"},
    "PASSPORT": {"category": "PII", "regulatory_basis": "GDPR Art.87, CCPA", "risk_level": "CRITICAL", "default_action": "REDACT"},
    "DRIVERS_LICENSE": {"category": "PII", "regulatory_basis": "GDPR Art.87, CCPA, HIPAA", "risk_level": "CRITICAL", "default_action": "REDACT"},
}

_SAMPLE_TEXTS = [
    {"name": "BFSI KYC", "description": "Banking KYC onboarding with SSN, credit card, and personal details",
     "text": "Customer John Smith, SSN 456-78-9012, applied for a credit card. Contact: john.smith@acmebank.com, phone (212) 555-0147. Card on file: 4111-1111-1111-1111. IP: 192.168.1.45."},
    {"name": "Healthcare Triage", "description": "Patient intake with PHI including names, dates, and identifiers",
     "text": "Dr. Sarah Mitchell referred patient Mr. James Rodriguez, DOB 03/15/1985, SSN 123-45-6789. Email: james.rodriguez@healthsys.org. Appointment scheduled 01/22/2025. Phone: +1 415-555-0198."},
    {"name": "Fintech Onboarding", "description": "Fintech account setup with IBAN, API keys, and PII",
     "text": "New merchant onboarding: Mrs. Priya Sharma, email priya.sharma@fintech.io. IBAN: DE89370400440532013000. API key for sandbox: sk-proj-abc123def456ghi789. Billing phone: (312) 555-0234."},
    {"name": "Legal Discovery", "description": "Legal document with multiple PII types and financial references",
     "text": "Re: Case #2024-7891. Deponent Ms. Elena Voronova, passport AB1234567, testified on 12/31/2024. Opposing counsel contacted at elena.voronova@lawfirm.com. Wire transfer to IBAN GB29NWBK60161331926819 confirmed."},
    {"name": "HR Employee Record", "description": "HR system extract with employee PII and credentials",
     "text": "Employee record: Dr. Sarah Mitchell, SSN 987-65-4321, hired 2025-01-22. Corporate email: sarah.mitchell@corp.com. Driver's license: D1234 5678 90123. Emergency contact: (646) 555-0312. VPN IP: 10.0.3.201. AWS key: AKIAIOSFODNN7EXAMPLE."},
]


class BatchScanRequest(BaseModel):
    texts: list[str]
    agent_id: Optional[str] = None
    policy_id: Optional[str] = None


class ProtectRequestEnhanced(BaseModel):
    text: str
    mode: str = "TOKENIZE"  # REDACT, TOKENIZE, PSEUDONYMIZE, GENERALIZE, ENCRYPT
    session_name: Optional[str] = None
    agent_id: Optional[str] = None
    policy_id: Optional[str] = None


class ValidateRequest(BaseModel):
    text: str


@router.post("/scan")
async def scan_text(req: dict):
    text = req.get("text", "")
    session_name = req.get("session_name")
    agent_id = req.get("agent_id")
    policy_id = req.get("policy_id")

    detections = detect(text)
    now = datetime.utcnow()
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO scan_sessions (name,created_at,expires_at,status,agent_id,policy_id,entities_protected,tokens_generated) VALUES (?,?,?,?,?,?,?,?)",
            (session_name or f"scan-{now.strftime('%Y%m%d%H%M%S')}",
             now.isoformat(), (now + timedelta(hours=24)).isoformat(),
             "ACTIVE", agent_id, policy_id, len(detections), 0))
        sid = cur.lastrowid
        for d in detections:
            await db.execute(
                "INSERT INTO entities_detected (session_id,entity_type,original_text,token,confidence,action,detected_at) VALUES (?,?,?,?,?,?,?)",
                (sid, d.entity_type, d.text, "", d.confidence, "DETECTED", now.isoformat()))
        await db.commit()
    finally:
        await db.close()

    entities = []
    for d in detections:
        entities.append({
            "entity_type": d.entity_type,
            "original_text": d.text,
            "start": d.start,
            "end": d.end,
            "confidence": d.confidence,
            "category": d.category or "CUSTOM",
            "regulatory_basis": d.regulatory_basis or "N/A",
            "risk_level": d.risk_level or "MEDIUM",
            "default_action": d.default_action or "TOKENIZE",
        })

    return {"session_id": sid, "entities": entities, "count": len(detections)}


@router.post("/protect")
async def protect_text(req: ProtectRequestEnhanced):
    t0 = time.monotonic()
    detections = detect(req.text)
    mode = req.mode.upper()

    sid = create_session(agent_id=req.agent_id or "demo-user", policy_id=req.policy_id or "default", ttl_seconds=3600)
    sanitized, vault_ref = tokenize(sid, req.text, detections, mode=mode)

    elapsed = time.monotonic() - t0

    now = datetime.utcnow()
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO scan_sessions (name,created_at,expires_at,status,agent_id,policy_id,entities_protected,tokens_generated) VALUES (?,?,?,?,?,?,?,?)",
            (req.session_name or f"protect-{now.strftime('%Y%m%d%H%M%S')}",
             now.isoformat(), (now + timedelta(hours=24)).isoformat(),
             "ACTIVE", req.agent_id, req.policy_id, len(detections), len(detections)))
        sid = cur.lastrowid
        for d in detections:
            token = f"<<{d.entity_type}>>"
            await db.execute(
                "INSERT INTO entities_detected (session_id,entity_type,original_text,token,confidence,action,detected_at) VALUES (?,?,?,?,?,?,?)",
                (sid, d.entity_type, d.text, token, d.confidence, mode, now.isoformat()))
        await db.commit()
    finally:
        await db.close()

    return {
        "session_id": sid,
        "sanitized_text": sanitized,
        "vault_ref": vault_ref,
        "entities_protected": len(detections),
        "tokens_generated": len(detections),
        "mode": mode,
        "latency_ms": round(elapsed * 1000, 1),
    }


@router.post("/restore")
async def restore_text(req: dict):
    vault_ref = req.get("vault_ref", "")
    result = restore(vault_ref)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Vault reference not found. The session may have expired or been purged.")
    original_text, count = result
    return {"original_text": original_text, "entities_restored": count}


@router.post("/scan/batch")
async def scan_batch(req: BatchScanRequest):
    """Scan multiple texts at once."""
    results = []
    total_entities = 0
    for i, text in enumerate(req.texts):
        detections = detect(text)
        total_entities += len(detections)
        entities = []
        for d in detections:
            entities.append({
                "entity_type": d.entity_type,
                "original_text": d.text,
                "start": d.start,
                "end": d.end,
                "confidence": d.confidence,
                "category": d.category or "CUSTOM",
                "risk_level": d.risk_level or "MEDIUM",
            })
        results.append({"index": i, "entities": entities, "count": len(detections)})

    return {"results": results, "total_texts": len(req.texts), "total_entities": total_entities}


@router.get("/scan/entity-registry")
async def entity_registry():
    """Return full entity type registry from detection engine."""
    return get_entity_registry()


@router.get("/scan/samples")
async def scan_samples():
    """Return pre-built sample texts for demo purposes."""
    return _SAMPLE_TEXTS


@router.post("/scan/validate")
async def validate_sanitized(req: ValidateRequest):
    """Validate that a text has been properly sanitized (no entities remain)."""
    detections = detect(req.text)
    if len(detections) == 0:
        return {
            "clean": True,
            "message": "Text is clean - no PII/PHI/PCI entities detected.",
            "entities_found": 0,
        }
    entities = []
    for d in detections:
        entities.append({
            "entity_type": d.entity_type,
            "original_text": d.text,
            "start": d.start,
            "end": d.end,
            "risk_level": d.risk_level or "MEDIUM",
        })
    return {
        "clean": False,
        "message": f"Sanitization incomplete: {len(detections)} entities still present.",
        "entities_found": len(detections),
        "remaining_entities": entities,
    }
