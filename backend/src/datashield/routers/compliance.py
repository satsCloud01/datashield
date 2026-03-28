"""Compliance framework endpoints — exhaustive assessment, controls, gaps, reporting."""
from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from datashield.database import get_db
from datashield.models.schemas import (
    ComplianceFrameworkOut, ComplianceSummary, ComplianceControlOut,
    ComplianceFrameworkDetail, ComplianceAssessmentResult,
    ComplianceReport, ComplianceGap,
)

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _row_to_fw(r) -> ComplianceFrameworkOut:
    return ComplianceFrameworkOut(
        id=r["id"], code=r["code"], name=r["name"], description=r["description"],
        category=r["category"], controls_total=r["controls_total"],
        controls_passing=r["controls_passing"], status=r["status"],
        last_assessed=r["last_assessed"])


def _row_to_control(r) -> ComplianceControlOut:
    return ComplianceControlOut(
        id=r["id"], framework_code=r["framework_code"], control_id=r["control_id"],
        name=r["name"], description=r["description"], status=r["status"],
        evidence_type=r["evidence_type"], last_checked=r["last_checked"],
        remediation_hint=r["remediation_hint"], severity=r["severity"])


@router.get("/frameworks", response_model=list[ComplianceFrameworkOut])
async def list_frameworks(category: Optional[str] = Query(None, description="Filter by category")):
    db = await get_db()
    try:
        if category:
            cur = await db.execute(
                "SELECT * FROM compliance_frameworks WHERE category=? ORDER BY code", (category,))
        else:
            cur = await db.execute("SELECT * FROM compliance_frameworks ORDER BY code")
        return [_row_to_fw(r) for r in await cur.fetchall()]
    finally:
        await db.close()


@router.get("/summary", response_model=ComplianceSummary)
async def compliance_summary():
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM compliance_frameworks")
        rows = await cur.fetchall()
        total_controls = sum(r["controls_total"] for r in rows)
        passing_controls = sum(r["controls_passing"] for r in rows)
        score = round((passing_controls / total_controls * 100) if total_controls else 0, 1)
        compliant = sum(1 for r in rows if r["status"] == "COMPLIANT")
        partial = sum(1 for r in rows if r["status"] == "PARTIAL")
        non_compliant = sum(1 for r in rows if r["status"] == "NON_COMPLIANT")

        # Top gaps: failing controls sorted by severity
        cur2 = await db.execute(
            "SELECT * FROM compliance_controls WHERE status='FAIL' ORDER BY "
            "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 END "
            "LIMIT 10")
        gaps = [ComplianceGap(
            framework_code=r["framework_code"], control_id=r["control_id"],
            name=r["name"], severity=r["severity"],
            remediation_hint=r["remediation_hint"]) for r in await cur2.fetchall()]

        return ComplianceSummary(
            overall_score=score, frameworks_total=len(rows),
            compliant=compliant, partial=partial, non_compliant=non_compliant,
            controls_total=total_controls, controls_passing=passing_controls,
            top_gaps=gaps)
    finally:
        await db.close()


@router.get("/gaps", response_model=list[ComplianceGap])
async def list_gaps():
    """List all failing controls across all frameworks, sorted by severity."""
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM compliance_controls WHERE status='FAIL' ORDER BY "
            "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 END")
        return [ComplianceGap(
            framework_code=r["framework_code"], control_id=r["control_id"],
            name=r["name"], severity=r["severity"],
            remediation_hint=r["remediation_hint"]) for r in await cur.fetchall()]
    finally:
        await db.close()


@router.get("/report", response_model=ComplianceReport)
async def compliance_report():
    """Generate a full compliance report with all frameworks, controls, and evidence."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM compliance_frameworks ORDER BY code")
        fw_rows = await cur.fetchall()

        frameworks = []
        total_controls = 0
        total_passing = 0
        for fw in fw_rows:
            cur2 = await db.execute(
                "SELECT * FROM compliance_controls WHERE framework_code=? ORDER BY control_id",
                (fw["code"],))
            controls = [_row_to_control(r) for r in await cur2.fetchall()]
            passing = sum(1 for c in controls if c.status == "PASS")
            failing = sum(1 for c in controls if c.status == "FAIL")
            total_controls += len(controls)
            total_passing += passing
            frameworks.append(ComplianceFrameworkDetail(
                **{k: fw[k] for k in ["id", "code", "name", "description", "category",
                                       "controls_total", "controls_passing", "status", "last_assessed"]},
                controls_failing=failing,
                controls=controls))

        score = round((total_passing / total_controls * 100) if total_controls else 0, 1)
        return ComplianceReport(
            generated_at=datetime.utcnow().isoformat(),
            overall_score=score,
            frameworks=frameworks,
            total_controls=total_controls,
            total_passing=total_passing,
            total_failing=total_controls - total_passing)
    finally:
        await db.close()


@router.get("/frameworks/{code}", response_model=ComplianceFrameworkDetail)
async def get_framework(code: str):
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM compliance_frameworks WHERE code=?", (code,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Framework not found")

        cur2 = await db.execute(
            "SELECT * FROM compliance_controls WHERE framework_code=? ORDER BY control_id",
            (code,))
        controls = [_row_to_control(r) for r in await cur2.fetchall()]
        passing = sum(1 for c in controls if c.status == "PASS")
        failing = sum(1 for c in controls if c.status == "FAIL")

        return ComplianceFrameworkDetail(
            id=row["id"], code=row["code"], name=row["name"],
            description=row["description"], category=row["category"],
            controls_total=row["controls_total"],
            controls_passing=passing,
            controls_failing=failing,
            status=row["status"], last_assessed=row["last_assessed"],
            controls=controls)
    finally:
        await db.close()


# Entity types required by each framework for automated assessment
_FRAMEWORK_REQUIRED_ENTITIES = {
    "GDPR": ["PERSON_NAME", "EMAIL", "PHONE", "IP_ADDRESS", "SSN"],
    "HIPAA": ["PERSON_NAME", "SSN", "DATE", "PHONE", "EMAIL"],
    "PCI-DSS-4": ["CREDIT_CARD", "IBAN", "API_KEY"],
    "CCPA": ["PERSON_NAME", "EMAIL", "PHONE", "SSN", "IP_ADDRESS"],
    "SOX": ["PERSON_NAME", "EMAIL"],
    "EU-AI-ACT": ["PERSON_NAME", "EMAIL"],
    "ISO-27701": ["PERSON_NAME", "EMAIL", "PHONE", "SSN"],
    "FERPA": ["PERSON_NAME", "EMAIL", "DATE", "SSN"],
}


@router.post("/assess/{code}", response_model=ComplianceAssessmentResult)
async def assess_framework(code: str):
    """Run automated assessment for a framework — check entity coverage, vault ops, audit trail."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM compliance_frameworks WHERE code=?", (code,))
        fw = await cur.fetchone()
        if not fw:
            raise HTTPException(404, "Framework not found")

        # Gather facts about system state
        # 1. Which entity types has the detection engine seen?
        cur2 = await db.execute("SELECT DISTINCT entity_type FROM entities_detected")
        detected_types = {r["entity_type"] for r in await cur2.fetchall()}

        # 2. Vault activity (tokenize actions = vault supports tokenization)
        cur3 = await db.execute("SELECT count(*) as c FROM entities_detected WHERE action='TOKENIZE'")
        tokenize_count = (await cur3.fetchone())["c"]

        # 3. Audit trail completeness
        cur4 = await db.execute("SELECT count(*) as c FROM audit_events")
        audit_count = (await cur4.fetchone())["c"]

        # 4. Check erasure support (PURGED sessions)
        cur5 = await db.execute("SELECT count(*) as c FROM scan_sessions WHERE status='PURGED'")
        purge_count = (await cur5.fetchone())["c"]

        required = set(_FRAMEWORK_REQUIRED_ENTITIES.get(code, []))
        covered = required & detected_types
        coverage_pct = round(len(covered) / len(required) * 100, 1) if required else 100.0

        # Update controls based on assessment
        now = datetime.utcnow().isoformat()
        cur6 = await db.execute(
            "SELECT * FROM compliance_controls WHERE framework_code=?", (code,))
        controls = await cur6.fetchall()

        checks_passed = 0
        findings = []
        for ctrl in controls:
            passed = True
            reason = ""
            eid = ctrl["evidence_type"]

            if eid == "ENTITY_DETECTION":
                passed = coverage_pct >= 80
                if not passed:
                    reason = f"Entity coverage {coverage_pct}% < 80% threshold"
            elif eid == "VAULT_OPERATION":
                passed = tokenize_count > 0
                if not passed:
                    reason = "No tokenization operations recorded in vault"
            elif eid == "AUDIT_TRAIL":
                passed = audit_count >= 10
                if not passed:
                    reason = f"Only {audit_count} audit events (minimum 10 required)"
            elif eid == "ERASURE_CAPABILITY":
                passed = purge_count > 0
                if not passed:
                    reason = "No erasure/purge operations demonstrated"
            elif eid == "POLICY_CONFIG":
                # Check if any active policy references this framework
                cur7 = await db.execute(
                    "SELECT count(*) as c FROM policies WHERE status='ACTIVE' AND compliance_packs LIKE ?",
                    (f"%{code}%",))
                pol_count = (await cur7.fetchone())["c"]
                passed = pol_count > 0
                if not passed:
                    reason = f"No active policy references {code}"
            else:
                # Default: pass if we have audit trail and detection
                passed = audit_count > 0 and len(detected_types) > 0

            new_status = "PASS" if passed else "FAIL"
            await db.execute(
                "UPDATE compliance_controls SET status=?, last_checked=? WHERE id=?",
                (new_status, now, ctrl["id"]))
            if passed:
                checks_passed += 1
            else:
                findings.append(f"[{ctrl['control_id']}] {ctrl['name']}: {reason or 'Assessment failed'}")

        # Update framework totals
        total = len(controls)
        fw_status = "COMPLIANT" if checks_passed / total > 0.85 else (
            "PARTIAL" if checks_passed / total > 0.65 else "NON_COMPLIANT") if total > 0 else "NOT_ASSESSED"
        await db.execute(
            "UPDATE compliance_frameworks SET controls_passing=?, status=?, last_assessed=? WHERE code=?",
            (checks_passed, fw_status, now, code))
        await db.commit()

        return ComplianceAssessmentResult(
            framework_code=code,
            status=fw_status,
            controls_total=total,
            controls_passing=checks_passed,
            controls_failing=total - checks_passed,
            entity_coverage_pct=coverage_pct,
            entity_types_covered=sorted(covered),
            entity_types_missing=sorted(required - covered),
            vault_active=tokenize_count > 0,
            audit_trail_count=audit_count,
            findings=findings,
            assessed_at=now)
    finally:
        await db.close()
