"""Scan session CRUD with filtering, pagination, audit trail, and vault purge."""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from datashield.database import get_db
from datashield.models.schemas import SessionCreate, SessionOut, SessionDetail, EntityOut, AuditEventOut

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _row_to_session(r) -> SessionOut:
    return SessionOut(id=r["id"], name=r["name"], created_at=r["created_at"],
                      expires_at=r["expires_at"], status=r["status"],
                      agent_id=r["agent_id"], policy_id=r["policy_id"],
                      entities_protected=r["entities_protected"], tokens_generated=r["tokens_generated"])


def _row_to_entity(e) -> EntityOut:
    return EntityOut(id=e["id"], session_id=e["session_id"], entity_type=e["entity_type"],
                     original_text=e["original_text"], token=e["token"], confidence=e["confidence"],
                     action=e["action"], detected_at=e["detected_at"])


def _row_to_audit(r) -> AuditEventOut:
    return AuditEventOut(
        id=r["id"], event_id=r["event_id"], event_type=r["event_type"],
        session_id=r["session_id"], agent_id=r["agent_id"], agent_role=r["agent_role"],
        policy_id=r["policy_id"], entities_json=r["entities_json"],
        latency_ms=r["latency_ms"], source_ip=r["source_ip"],
        target_service=r["target_service"], timestamp=r["timestamp"],
        hash=r["hash"], prev_hash=r["prev_hash"])


@router.get("", response_model=list[SessionOut])
async def list_sessions(
    status: Optional[str] = Query(None, description="Filter by status: ACTIVE, EXPIRED, PURGED"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    date_from: Optional[str] = Query(None, description="Filter from date (ISO format)"),
    date_to: Optional[str] = Query(None, description="Filter to date (ISO format)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    db = await get_db()
    try:
        conditions = []
        params = []
        if status:
            conditions.append("status=?")
            params.append(status)
        if agent_id:
            conditions.append("agent_id=?")
            params.append(agent_id)
        if date_from:
            conditions.append("created_at>=?")
            params.append(date_from)
        if date_to:
            conditions.append("created_at<=?")
            params.append(date_to)

        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        query = f"SELECT * FROM scan_sessions{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = await db.execute(query, params)
        rows = await cur.fetchall()

        # Get total count for pagination
        count_query = f"SELECT count(*) as c FROM scan_sessions{where}"
        cur2 = await db.execute(count_query, params[:-2] if conditions else [])
        total = (await cur2.fetchone())["c"]

        sessions = [_row_to_session(r) for r in rows]
        return sessions
    finally:
        await db.close()


@router.post("", response_model=SessionOut, status_code=201)
async def create_session(req: SessionCreate):
    now = datetime.utcnow()
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO scan_sessions (name,created_at,expires_at,status,agent_id,policy_id,entities_protected,tokens_generated) VALUES (?,?,?,?,?,?,?,?)",
            (req.name, now.isoformat(), (now + timedelta(hours=24)).isoformat(), "ACTIVE", req.agent_id, req.policy_id, 0, 0))
        await db.commit()
        sid = cur.lastrowid
        cur2 = await db.execute("SELECT * FROM scan_sessions WHERE id=?", (sid,))
        row = await cur2.fetchone()
        return _row_to_session(row)
    finally:
        await db.close()


@router.get("/{session_id}")
async def get_session(session_id: int):
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM scan_sessions WHERE id=?", (session_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        # Entities
        cur2 = await db.execute(
            "SELECT * FROM entities_detected WHERE session_id=? ORDER BY detected_at", (session_id,))
        entities = [_row_to_entity(e) for e in await cur2.fetchall()]

        # Audit events
        cur3 = await db.execute(
            "SELECT * FROM audit_events WHERE session_id=? ORDER BY timestamp", (session_id,))
        audit_events = [_row_to_audit(a) for a in await cur3.fetchall()]

        # Vault stats
        tokenized = sum(1 for e in entities if e.action == "TOKENIZE")
        redacted = sum(1 for e in entities if e.action == "REDACT")
        masked = sum(1 for e in entities if e.action == "MASK")

        session_data = dict(row)
        session_data["entities"] = [e.model_dump() for e in entities]
        session_data["audit_events"] = [a.model_dump() for a in audit_events]
        session_data["vault_stats"] = {
            "tokenized": tokenized,
            "redacted": redacted,
            "masked": masked,
            "total_entities": len(entities),
            "total_audit_events": len(audit_events),
        }
        return session_data
    finally:
        await db.close()


@router.get("/{session_id}/entities", response_model=list[EntityOut])
async def get_session_entities(session_id: int):
    """List all entities detected in a session."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT id FROM scan_sessions WHERE id=?", (session_id,))
        if not await cur.fetchone():
            raise HTTPException(404, "Session not found")
        cur2 = await db.execute(
            "SELECT * FROM entities_detected WHERE session_id=? ORDER BY detected_at", (session_id,))
        return [_row_to_entity(e) for e in await cur2.fetchall()]
    finally:
        await db.close()


@router.get("/{session_id}/audit", response_model=list[AuditEventOut])
async def get_session_audit(session_id: int):
    """All audit events for a session."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT id FROM scan_sessions WHERE id=?", (session_id,))
        if not await cur.fetchone():
            raise HTTPException(404, "Session not found")
        cur2 = await db.execute(
            "SELECT * FROM audit_events WHERE session_id=? ORDER BY timestamp", (session_id,))
        return [_row_to_audit(r) for r in await cur2.fetchall()]
    finally:
        await db.close()


@router.post("/{session_id}/extend")
async def extend_session(session_id: int, hours: int = Query(24, ge=1, le=168)):
    """Extend session TTL."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM scan_sessions WHERE id=?", (session_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Session not found")
        if row["status"] == "PURGED":
            raise HTTPException(400, "Cannot extend a purged session")

        current_expires = row["expires_at"]
        try:
            exp_dt = datetime.fromisoformat(current_expires)
        except (ValueError, TypeError):
            exp_dt = datetime.utcnow()
        new_expires = (exp_dt + timedelta(hours=hours)).isoformat()

        await db.execute(
            "UPDATE scan_sessions SET expires_at=?, status='ACTIVE' WHERE id=?",
            (new_expires, session_id))

        # Log audit event
        now = datetime.utcnow().isoformat()
        eid = f"evt_{uuid.uuid4().hex[:10]}"
        raw = f"{eid}SESSION_EXTEND{now}"
        cur_hash = hashlib.sha256(raw.encode()).hexdigest()
        await db.execute(
            "INSERT INTO audit_events (event_id,event_type,session_id,agent_id,agent_role,policy_id,entities_json,latency_ms,source_ip,target_service,timestamp,hash,prev_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, "SESSION_EXTEND", session_id, row["agent_id"], None, row["policy_id"],
             json.dumps({"hours_added": hours}), 0, None, "session-manager", now, cur_hash, ""))
        await db.commit()

        return {
            "session_id": session_id,
            "previous_expires": current_expires,
            "new_expires": new_expires,
            "hours_added": hours,
            "status": "ACTIVE",
        }
    finally:
        await db.close()


@router.delete("/{session_id}", status_code=204)
async def purge_session(session_id: int):
    """Purge session: mark as PURGED, delete entities (vault mappings), log audit event."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM scan_sessions WHERE id=?", (session_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Session not found")

        # Count entities being purged
        cur2 = await db.execute(
            "SELECT count(*) as c FROM entities_detected WHERE session_id=?", (session_id,))
        entity_count = (await cur2.fetchone())["c"]

        # Delete entities (vault mappings)
        await db.execute("DELETE FROM entities_detected WHERE session_id=?", (session_id,))
        await db.execute("UPDATE scan_sessions SET status='PURGED', entities_protected=0, tokens_generated=0 WHERE id=?", (session_id,))

        # Log audit event
        now = datetime.utcnow().isoformat()
        eid = f"evt_{uuid.uuid4().hex[:10]}"
        raw = f"{eid}SESSION_PURGE{now}"
        cur_hash = hashlib.sha256(raw.encode()).hexdigest()
        await db.execute(
            "INSERT INTO audit_events (event_id,event_type,session_id,agent_id,agent_role,policy_id,entities_json,latency_ms,source_ip,target_service,timestamp,hash,prev_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, "SESSION_PURGE", session_id, row["agent_id"], None, row["policy_id"],
             json.dumps({"entities_purged": entity_count}), 0, None, "session-manager", now, cur_hash, ""))
        await db.commit()
    finally:
        await db.close()
