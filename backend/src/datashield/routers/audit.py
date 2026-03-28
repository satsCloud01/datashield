"""Audit trail: events, stats, hash-chain verification, export, and session trails."""
from __future__ import annotations
import hashlib
import json
import time
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from datashield.database import get_db
from datashield.models.schemas import (
    AuditEventOut, AuditEventDetail, AuditStats,
    AuditVerifyResponse, AuditAgentSummary, AuditSessionTrail,
)

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _row_to_event(r) -> AuditEventOut:
    return AuditEventOut(
        id=r["id"], event_id=r["event_id"], event_type=r["event_type"],
        session_id=r["session_id"], agent_id=r["agent_id"], agent_role=r["agent_role"],
        policy_id=r["policy_id"], entities_json=r["entities_json"],
        latency_ms=r["latency_ms"], source_ip=r["source_ip"],
        target_service=r["target_service"], timestamp=r["timestamp"],
        hash=r["hash"], prev_hash=r["prev_hash"])


# ── GET /api/audit/events ────────────────────────────────────────────

@router.get("/events", response_model=list[AuditEventOut])
async def list_events(
    event_type: str | None = None,
    agent_id: str | None = None,
    session_id: int | None = None,
    policy_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    entity_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    db = await get_db()
    try:
        clauses, params = [], []
        if event_type:
            clauses.append("event_type=?"); params.append(event_type)
        if agent_id:
            clauses.append("agent_id=?"); params.append(agent_id)
        if session_id is not None:
            clauses.append("session_id=?"); params.append(session_id)
        if policy_id:
            clauses.append("policy_id=?"); params.append(policy_id)
        if date_from:
            clauses.append("timestamp>=?"); params.append(date_from)
        if date_to:
            clauses.append("timestamp<=?"); params.append(date_to)
        if entity_type:
            clauses.append("entities_json LIKE ?"); params.append(f'%"{entity_type}"%')
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params += [limit, offset]
        cur = await db.execute(
            f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?", params)
        return [_row_to_event(r) for r in await cur.fetchall()]
    finally:
        await db.close()


# ── GET /api/audit/events/{event_id} ────────────────────────────────

@router.get("/events/{event_id}", response_model=AuditEventDetail)
async def get_event(event_id: str):
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM audit_events WHERE event_id=?", (event_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Audit event '{event_id}' not found")

        base = _row_to_event(row)

        # Find prev and next in chain
        prev_hash = None
        next_hash = None
        if row["prev_hash"] and row["prev_hash"] != "0" * 64:
            cur2 = await db.execute("SELECT hash FROM audit_events WHERE hash=?", (row["prev_hash"],))
            prev_row = await cur2.fetchone()
            if prev_row:
                prev_hash = prev_row["hash"]

        cur3 = await db.execute("SELECT hash FROM audit_events WHERE prev_hash=?", (row["hash"],))
        next_row = await cur3.fetchone()
        if next_row:
            next_hash = next_row["hash"]

        return AuditEventDetail(
            **base.model_dump(),
            prev_event_hash=prev_hash,
            next_event_hash=next_hash,
        )
    finally:
        await db.close()


# ── GET /api/audit/stats ─────────────────────────────────────────────

@router.get("/stats", response_model=AuditStats)
async def audit_stats():
    db = await get_db()
    try:
        cur = await db.execute("SELECT count(*) as c FROM audit_events")
        total = (await cur.fetchone())["c"]

        cur2 = await db.execute("SELECT event_type, count(*) as c FROM audit_events GROUP BY event_type")
        by_type = {r["event_type"]: r["c"] for r in await cur2.fetchall()}

        cur3 = await db.execute("SELECT agent_id, count(*) as c FROM audit_events WHERE agent_id IS NOT NULL GROUP BY agent_id")
        by_agent = {r["agent_id"]: r["c"] for r in await cur3.fetchall()}

        cur4 = await db.execute(
            "SELECT substr(timestamp,1,13) as hour, count(*) as c FROM audit_events GROUP BY hour ORDER BY hour DESC LIMIT 24")
        by_hour = [{"hour": r["hour"], "count": r["c"]} for r in await cur4.fetchall()]

        # Entity type distribution from entities_json
        cur5 = await db.execute("SELECT entities_json FROM audit_events WHERE entities_json IS NOT NULL")
        entity_counts: dict[str, int] = {}
        for r in await cur5.fetchall():
            try:
                entities = json.loads(r["entities_json"])
                if isinstance(entities, list):
                    for e in entities:
                        if isinstance(e, dict):
                            etype = e.get("type", "UNKNOWN")
                        else:
                            etype = str(e)
                        entity_counts[etype] = entity_counts.get(etype, 0) + 1
                elif isinstance(entities, str):
                    for etype in entities.split(","):
                        etype = etype.strip()
                        if etype:
                            entity_counts[etype] = entity_counts.get(etype, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        cur6 = await db.execute("SELECT avg(latency_ms) as a FROM audit_events WHERE latency_ms IS NOT NULL")
        avg_lat = (await cur6.fetchone())["a"] or 0.0

        # Peak hour
        peak_hour = by_hour[0]["hour"] if by_hour else None

        cur7 = await db.execute("SELECT count(DISTINCT agent_id) as c FROM audit_events WHERE agent_id IS NOT NULL")
        unique_agents = (await cur7.fetchone())["c"]

        cur8 = await db.execute("SELECT count(DISTINCT session_id) as c FROM audit_events WHERE session_id IS NOT NULL")
        unique_sessions = (await cur8.fetchone())["c"]

        return AuditStats(
            total=total,
            by_type=by_type,
            by_agent=by_agent,
            by_hour=by_hour,
            by_entity_type=entity_counts,
            avg_latency=round(avg_lat, 1),
            peak_hour=peak_hour,
            unique_agents=unique_agents,
            unique_sessions=unique_sessions,
        )
    finally:
        await db.close()


# ── GET /api/audit/verify ────────────────────────────────────────────

@router.get("/verify", response_model=AuditVerifyResponse)
async def verify_chain():
    t0 = time.monotonic()
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM audit_events ORDER BY id ASC")
        rows = await cur.fetchall()
        if not rows:
            return AuditVerifyResponse(
                verified=True, total_events=0, chain_length=0,
                broken_links=[], first_event=None, last_event=None,
                verification_time_ms=round((time.monotonic() - t0) * 1000, 2))

        broken: list[dict] = []
        for i in range(1, len(rows)):
            expected_prev = rows[i - 1]["hash"]
            actual_prev = rows[i]["prev_hash"]
            if actual_prev != expected_prev:
                broken.append({
                    "position": i,
                    "event_id": rows[i]["event_id"],
                    "expected_prev_hash": expected_prev,
                    "actual_prev_hash": actual_prev,
                })

        elapsed = round((time.monotonic() - t0) * 1000, 2)
        return AuditVerifyResponse(
            verified=len(broken) == 0,
            total_events=len(rows),
            chain_length=len(rows),
            broken_links=broken,
            first_event=rows[0]["event_id"],
            last_event=rows[-1]["event_id"],
            verification_time_ms=elapsed,
        )
    finally:
        await db.close()


# ── GET /api/audit/export ────────────────────────────────────────────

@router.get("/export")
async def export_events(
    event_type: str | None = None,
    agent_id: str | None = None,
    session_id: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    db = await get_db()
    try:
        clauses, params = [], []
        if event_type:
            clauses.append("event_type=?"); params.append(event_type)
        if agent_id:
            clauses.append("agent_id=?"); params.append(agent_id)
        if session_id is not None:
            clauses.append("session_id=?"); params.append(session_id)
        if date_from:
            clauses.append("timestamp>=?"); params.append(date_from)
        if date_to:
            clauses.append("timestamp<=?"); params.append(date_to)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cur = await db.execute(f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC", params)
        rows = await cur.fetchall()
        events = [_row_to_event(r).model_dump() for r in rows]
        return JSONResponse(
            content=events,
            headers={"Content-Disposition": "attachment; filename=audit_export.json"},
            media_type="application/json",
        )
    finally:
        await db.close()


# ── GET /api/audit/agents ────────────────────────────────────────────

@router.get("/agents", response_model=list[AuditAgentSummary])
async def list_agents():
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT agent_id, count(*) as c FROM audit_events WHERE agent_id IS NOT NULL GROUP BY agent_id ORDER BY c DESC")
        return [AuditAgentSummary(agent_id=r["agent_id"], event_count=r["c"]) for r in await cur.fetchall()]
    finally:
        await db.close()


# ── GET /api/audit/sessions/{session_id} ─────────────────────────────

@router.get("/sessions/{session_id}", response_model=AuditSessionTrail)
async def session_trail(session_id: int):
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM audit_events WHERE session_id=? ORDER BY timestamp ASC", (session_id,))
        rows = await cur.fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail=f"No audit events for session {session_id}")
        return AuditSessionTrail(
            session_id=session_id,
            events=[_row_to_event(r) for r in rows],
        )
    finally:
        await db.close()
