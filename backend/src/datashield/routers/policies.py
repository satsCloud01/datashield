"""Policy CRUD with YAML validation."""
from __future__ import annotations
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException

from datashield.database import get_db
from datashield.models.schemas import PolicyCreate, PolicyUpdate, PolicyOut
from datashield.services.policy_engine import validate_yaml

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _row_to_policy(r) -> PolicyOut:
    packs = json.loads(r["compliance_packs"]) if r["compliance_packs"] else []
    return PolicyOut(id=r["id"], policy_id=r["policy_id"], name=r["name"],
                     description=r["description"] or "", yaml_content=r["yaml_content"],
                     status=r["status"], compliance_packs=packs,
                     created_at=r["created_at"], updated_at=r["updated_at"])


@router.get("", response_model=list[PolicyOut])
async def list_policies(status: str | None = None):
    db = await get_db()
    try:
        if status:
            cur = await db.execute("SELECT * FROM policies WHERE status=? ORDER BY created_at DESC", (status,))
        else:
            cur = await db.execute("SELECT * FROM policies ORDER BY created_at DESC")
        return [_row_to_policy(r) for r in await cur.fetchall()]
    finally:
        await db.close()


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(req: PolicyCreate):
    valid, msg = validate_yaml(req.yaml_content)
    if not valid:
        raise HTTPException(400, msg)
    now = datetime.utcnow().isoformat()
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO policies (policy_id,name,description,yaml_content,status,compliance_packs,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (req.policy_id, req.name, req.description, req.yaml_content, req.status,
             json.dumps(req.compliance_packs), now, now))
        await db.commit()
        cur2 = await db.execute("SELECT * FROM policies WHERE id=?", (cur.lastrowid,))
        return _row_to_policy(await cur2.fetchone())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, f"Policy ID '{req.policy_id}' already exists")
        raise
    finally:
        await db.close()


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(policy_id: str):
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM policies WHERE policy_id=? OR id=?", (policy_id, policy_id if policy_id.isdigit() else -1))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Policy not found")
        return _row_to_policy(row)
    finally:
        await db.close()


@router.put("/{policy_id}", response_model=PolicyOut)
async def update_policy(policy_id: str, req: PolicyUpdate):
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM policies WHERE policy_id=?", (policy_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Policy not found")

        updates = {}
        if req.name is not None:
            updates["name"] = req.name
        if req.description is not None:
            updates["description"] = req.description
        if req.yaml_content is not None:
            valid, msg = validate_yaml(req.yaml_content)
            if not valid:
                raise HTTPException(400, msg)
            updates["yaml_content"] = req.yaml_content
        if req.status is not None:
            updates["status"] = req.status
        if req.compliance_packs is not None:
            updates["compliance_packs"] = json.dumps(req.compliance_packs)
        updates["updated_at"] = datetime.utcnow().isoformat()

        sets = ", ".join(f"{k}=?" for k in updates)
        vals = list(updates.values()) + [policy_id]
        await db.execute(f"UPDATE policies SET {sets} WHERE policy_id=?", vals)
        await db.commit()
        cur2 = await db.execute("SELECT * FROM policies WHERE policy_id=?", (policy_id,))
        return _row_to_policy(await cur2.fetchone())
    finally:
        await db.close()
