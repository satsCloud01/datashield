"""Settings router — GET/PUT settings + agent role CRUD."""
from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException

from datashield.database import get_db
from datashield.models.schemas import (
    SettingsOut,
    SettingsUpdate,
    AgentRoleOut,
    AgentRoleCreate,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


# ── Helpers ──────────────────────────────────────────────────────────

def _row_to_settings(row) -> dict:
    return {
        "vault_ttl": row["vault_ttl"],
        "session_timeout": row["session_timeout"],
        "confidence_threshold": row["confidence_threshold"],
        "enabled_entity_types": json.loads(row["enabled_entity_types"]),
        "notification_email_enabled": bool(row["notification_email_enabled"]),
        "notification_slack_enabled": bool(row["notification_slack_enabled"]),
        "notification_siem_enabled": bool(row["notification_siem_enabled"]),
        "notification_webhook_enabled": bool(row["notification_webhook_enabled"]),
        "webhook_url": row["webhook_url"],
    }


def _row_to_role(row) -> dict:
    return {
        "id": row["id"],
        "role_name": row["role_name"],
        "description": row["description"],
        "permissions": json.loads(row["permissions"]),
        "is_default": bool(row["is_default"]),
    }


# ── Settings CRUD ────────────────────────────────────────────────────

@router.get("", response_model=SettingsOut)
async def get_settings():
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM settings LIMIT 1")
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Settings not initialized")
        return _row_to_settings(row)
    finally:
        await db.close()


@router.put("", response_model=SettingsOut)
async def update_settings(body: SettingsUpdate):
    db = await get_db()
    try:
        # Build SET clause from non-None fields
        updates = {}
        data = body.model_dump(exclude_unset=True)
        if "vault_ttl" in data:
            updates["vault_ttl"] = data["vault_ttl"]
        if "session_timeout" in data:
            updates["session_timeout"] = data["session_timeout"]
        if "confidence_threshold" in data:
            updates["confidence_threshold"] = data["confidence_threshold"]
        if "enabled_entity_types" in data:
            updates["enabled_entity_types"] = json.dumps(data["enabled_entity_types"])
        if "notification_email_enabled" in data:
            updates["notification_email_enabled"] = int(data["notification_email_enabled"])
        if "notification_slack_enabled" in data:
            updates["notification_slack_enabled"] = int(data["notification_slack_enabled"])
        if "notification_siem_enabled" in data:
            updates["notification_siem_enabled"] = int(data["notification_siem_enabled"])
        if "notification_webhook_enabled" in data:
            updates["notification_webhook_enabled"] = int(data["notification_webhook_enabled"])
        if "webhook_url" in data:
            updates["webhook_url"] = data["webhook_url"]

        if not updates:
            raise HTTPException(400, "No fields to update")

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values())
        await db.execute(f"UPDATE settings SET {set_clause} WHERE id = 1", values)
        await db.commit()

        cur = await db.execute("SELECT * FROM settings LIMIT 1")
        row = await cur.fetchone()
        return _row_to_settings(row)
    finally:
        await db.close()


# ── Agent roles ──────────────────────────────────────────────────────

@router.get("/agent-roles", response_model=list[AgentRoleOut])
async def list_agent_roles():
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM agent_roles ORDER BY id")
        rows = await cur.fetchall()
        return [_row_to_role(r) for r in rows]
    finally:
        await db.close()


@router.post("/agent-roles", response_model=AgentRoleOut, status_code=201)
async def create_agent_role(body: AgentRoleCreate):
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO agent_roles (role_name, description, permissions, is_default) VALUES (?, ?, ?, ?)",
            (body.role_name, body.description, json.dumps(body.permissions), int(body.is_default)),
        )
        await db.commit()
        role_id = cur.lastrowid
        cur2 = await db.execute("SELECT * FROM agent_roles WHERE id = ?", (role_id,))
        row = await cur2.fetchone()
        return _row_to_role(row)
    finally:
        await db.close()


@router.delete("/agent-roles/{role_id}", status_code=204)
async def delete_agent_role(role_id: int):
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM agent_roles WHERE id = ?", (role_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, f"Agent role {role_id} not found")
        await db.execute("DELETE FROM agent_roles WHERE id = ?", (role_id,))
        await db.commit()
    finally:
        await db.close()
