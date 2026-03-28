"""Dashboard aggregate endpoints — exhaustive stats, timelines, heatmaps."""
from __future__ import annotations
import json
from fastapi import APIRouter

from datashield.database import get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

# Entity type → category mapping
_ENTITY_CATEGORIES = {
    "SSN": "PII", "EMAIL": "PII", "PHONE": "PII", "PERSON_NAME": "PII",
    "IP_ADDRESS": "PII", "PASSPORT": "PII", "DRIVERS_LICENSE": "PII",
    "DATE": "PHI", "CREDIT_CARD": "PCI", "IBAN": "FINANCIAL",
    "API_KEY": "IP_CODE",
}

_SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@router.get("/stats")
async def dashboard_stats():
    db = await get_db()
    try:
        cur = await db.execute("SELECT count(*) as c FROM scan_sessions")
        total_scans = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT coalesce(sum(entities_protected),0) as s FROM scan_sessions")
        entities_protected = (await cur.fetchone())["s"]

        cur = await db.execute("SELECT count(*) as c FROM scan_sessions WHERE status='ACTIVE'")
        active_sessions = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT count(*) as c FROM scan_sessions WHERE status='EXPIRED'")
        expired_sessions = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT count(*) as c FROM threat_events WHERE status='BLOCKED'")
        threats_blocked = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT count(*) as c FROM threat_events WHERE status='FLAGGED'")
        threats_flagged = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT coalesce(avg(latency_ms),0) as a FROM audit_events")
        avg_latency = round((await cur.fetchone())["a"], 1)

        cur = await db.execute(
            "SELECT coalesce(sum(controls_passing),0) as p, coalesce(sum(controls_total),0) as t FROM compliance_frameworks")
        row = await cur.fetchone()
        compliance_score = round((row["p"] / row["t"] * 100) if row["t"] else 0, 1)

        # Vault utilization: count of active tokens (entities with action=TOKENIZE in active sessions)
        cur = await db.execute(
            "SELECT count(*) as c FROM entities_detected e JOIN scan_sessions s ON e.session_id=s.id "
            "WHERE e.action='TOKENIZE' AND s.status='ACTIVE'")
        vault_utilization = (await cur.fetchone())["c"]

        # Detection accuracy: entities with confidence > 0.9 / total
        cur = await db.execute("SELECT count(*) as total, "
                               "sum(CASE WHEN confidence > 0.9 THEN 1 ELSE 0 END) as high_conf "
                               "FROM entities_detected")
        acc_row = await cur.fetchone()
        detection_accuracy = round(
            (acc_row["high_conf"] / acc_row["total"] * 100) if acc_row["total"] else 0, 1)

        # Risk score: weighted threat severity
        cur = await db.execute("SELECT severity, count(*) as c FROM threat_events GROUP BY severity")
        sev_rows = await cur.fetchall()
        total_weight = sum(_SEVERITY_WEIGHTS.get(r["severity"], 1) * r["c"] for r in sev_rows)
        total_threats = sum(r["c"] for r in sev_rows) or 1
        risk_score = round(total_weight / total_threats, 2)

        return {
            "total_scans": total_scans,
            "entities_protected": entities_protected,
            "active_sessions": active_sessions,
            "expired_sessions": expired_sessions,
            "threats_blocked": threats_blocked,
            "threats_flagged": threats_flagged,
            "avg_latency_ms": avg_latency,
            "compliance_score": compliance_score,
            "vault_utilization": vault_utilization,
            "detection_accuracy": detection_accuracy,
            "risk_score": risk_score,
        }
    finally:
        await db.close()


@router.get("/timeline")
async def dashboard_timeline():
    """Entities protected per hour for last 24h, with breakdown by entity category."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT substr(detected_at,1,13) as hour, entity_type, count(*) as c "
            "FROM entities_detected GROUP BY hour, entity_type ORDER BY hour DESC LIMIT 200")
        rows = await cur.fetchall()

        # Aggregate by hour with category breakdown
        hours: dict[str, dict] = {}
        for r in rows:
            h = r["hour"]
            cat = _ENTITY_CATEGORIES.get(r["entity_type"], "CUSTOM")
            if h not in hours:
                hours[h] = {"hour": h, "total": 0, "PII": 0, "PHI": 0, "PCI": 0,
                            "FINANCIAL": 0, "IP_CODE": 0, "CUSTOM": 0}
            hours[h]["total"] += r["c"]
            hours[h][cat] = hours[h].get(cat, 0) + r["c"]

        result = sorted(hours.values(), key=lambda x: x["hour"], reverse=True)[:24]
        return result
    finally:
        await db.close()


@router.get("/entity-distribution")
async def entity_distribution():
    """Entity distribution by type AND by category."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT entity_type, count(*) as c FROM entities_detected GROUP BY entity_type ORDER BY c DESC")
        by_type = [{"entity_type": r["entity_type"], "count": r["c"],
                     "category": _ENTITY_CATEGORIES.get(r["entity_type"], "CUSTOM")}
                    for r in await cur.fetchall()]

        # Aggregate by category
        cats: dict[str, int] = {}
        for item in by_type:
            cats[item["category"]] = cats.get(item["category"], 0) + item["count"]
        by_category = [{"category": k, "count": v} for k, v in sorted(cats.items(), key=lambda x: -x[1])]

        return {"by_type": by_type, "by_category": by_category}
    finally:
        await db.close()


@router.get("/threat-summary")
async def threat_summary():
    """Recent threats with severity distribution and trend."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT 20")
        recent = []
        for r in await cur.fetchall():
            recent.append({
                "id": r["id"], "threat_type": r["threat_type"], "severity": r["severity"],
                "agent_id": r["agent_id"], "description": r["description"],
                "status": r["status"], "timestamp": r["timestamp"]})

        cur = await db.execute(
            "SELECT severity, count(*) as c FROM threat_events GROUP BY severity")
        severity_dist = {r["severity"]: r["c"] for r in await cur.fetchall()}

        # Trend: compare last 24h vs previous 24h
        cur = await db.execute(
            "SELECT count(*) as c FROM threat_events WHERE timestamp >= datetime('now', '-1 day')")
        last_24 = (await cur.fetchone())["c"]
        cur = await db.execute(
            "SELECT count(*) as c FROM threat_events WHERE timestamp >= datetime('now', '-2 day') "
            "AND timestamp < datetime('now', '-1 day')")
        prev_24 = (await cur.fetchone())["c"]
        trend = "increasing" if last_24 > prev_24 else ("decreasing" if last_24 < prev_24 else "stable")

        return {
            "recent_threats": recent,
            "severity_distribution": severity_dist,
            "last_24h": last_24,
            "previous_24h": prev_24,
            "trend": trend,
        }
    finally:
        await db.close()


@router.get("/agent-activity")
async def agent_activity():
    """List agents with their scan count, entities detected, threats triggered."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT agent_id, count(*) as scan_count, sum(entities_protected) as entities_detected "
            "FROM scan_sessions WHERE agent_id IS NOT NULL GROUP BY agent_id ORDER BY scan_count DESC")
        agents = {}
        for r in await cur.fetchall():
            agents[r["agent_id"]] = {
                "agent_id": r["agent_id"],
                "scan_count": r["scan_count"],
                "entities_detected": r["entities_detected"] or 0,
                "threats_triggered": 0,
            }

        cur = await db.execute(
            "SELECT agent_id, count(*) as c FROM threat_events WHERE agent_id IS NOT NULL GROUP BY agent_id")
        for r in await cur.fetchall():
            if r["agent_id"] in agents:
                agents[r["agent_id"]]["threats_triggered"] = r["c"]
            else:
                agents[r["agent_id"]] = {
                    "agent_id": r["agent_id"], "scan_count": 0,
                    "entities_detected": 0, "threats_triggered": r["c"]}

        return list(agents.values())
    finally:
        await db.close()


@router.get("/top-entities")
async def top_entities():
    """Top 10 most frequently detected entity types."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT entity_type, count(*) as c, avg(confidence) as avg_conf "
            "FROM entities_detected GROUP BY entity_type ORDER BY c DESC LIMIT 10")
        return [{"entity_type": r["entity_type"], "count": r["c"],
                 "avg_confidence": round(r["avg_conf"], 3),
                 "category": _ENTITY_CATEGORIES.get(r["entity_type"], "CUSTOM")}
                for r in await cur.fetchall()]
    finally:
        await db.close()


@router.get("/surface-activity")
async def surface_activity():
    """Interception counts by surface with trends."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT surface, count(*) as total, "
            "sum(CASE WHEN action_taken='BLOCKED' THEN 1 ELSE 0 END) as blocked, "
            "sum(CASE WHEN action_taken='TOKENIZED' THEN 1 ELSE 0 END) as tokenized, "
            "sum(CASE WHEN action_taken='LOGGED' THEN 1 ELSE 0 END) as logged, "
            "avg(latency_ms) as avg_latency, sum(entities_found) as total_entities "
            "FROM interceptor_logs GROUP BY surface ORDER BY total DESC")
        surfaces = []
        for r in await cur.fetchall():
            surfaces.append({
                "surface": r["surface"],
                "total_intercepts": r["total"],
                "blocked": r["blocked"],
                "tokenized": r["tokenized"],
                "logged": r["logged"],
                "total_entities": r["total_entities"],
                "avg_latency_ms": round(r["avg_latency"], 1),
            })
        return surfaces
    finally:
        await db.close()


@router.get("/risk-heatmap")
async def risk_heatmap():
    """Risk scores by agent + entity type combination (matrix data for heatmap)."""
    db = await get_db()
    try:
        # Get entity counts per agent per entity type
        cur = await db.execute(
            "SELECT s.agent_id, e.entity_type, count(*) as c, avg(e.confidence) as avg_conf "
            "FROM entities_detected e JOIN scan_sessions s ON e.session_id=s.id "
            "WHERE s.agent_id IS NOT NULL "
            "GROUP BY s.agent_id, e.entity_type")
        rows = await cur.fetchall()

        # Get threat counts per agent
        cur2 = await db.execute(
            "SELECT agent_id, count(*) as c, "
            "sum(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) as weight "
            "FROM threat_events WHERE agent_id IS NOT NULL GROUP BY agent_id")
        threat_weights = {r["agent_id"]: r["weight"] for r in await cur2.fetchall()}

        # Build heatmap cells
        cells = []
        for r in rows:
            agent = r["agent_id"]
            # Risk = entity frequency * (1 - confidence) + threat weight contribution
            base_risk = r["c"] * (1 - r["avg_conf"])
            threat_bonus = threat_weights.get(agent, 0) * 0.1
            risk = round(min(base_risk + threat_bonus, 10.0), 2)
            cells.append({
                "agent_id": agent,
                "entity_type": r["entity_type"],
                "count": r["c"],
                "avg_confidence": round(r["avg_conf"], 3),
                "risk_score": risk,
            })

        # Collect axes
        agents = sorted({c["agent_id"] for c in cells})
        entity_types = sorted({c["entity_type"] for c in cells})

        return {"agents": agents, "entity_types": entity_types, "cells": cells}
    finally:
        await db.close()
