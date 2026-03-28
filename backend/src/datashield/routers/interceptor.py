"""Interceptor logs, simulation, batch processing, and surface metadata."""
from __future__ import annotations
import re
import time
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException

from datashield.database import get_db
from datashield.models.schemas import (
    InterceptorLogOut, InterceptSimulateRequest, InterceptSimulateResponse,
    InterceptorStats, DetectedEntity, PolicyDecision,
    InterceptBatchRequest, InterceptBatchResponse, SurfaceInfo,
)
from datashield.services.detection_engine import detect

router = APIRouter(prefix="/api/interceptor", tags=["interceptor"])

# ── Severity weights for risk scoring ────────────────────────────────
_SEVERITY_WEIGHTS: dict[str, float] = {
    "SSN": 25, "CREDIT_CARD": 25, "IBAN": 20, "API_KEY": 30,
    "EMAIL": 8, "PHONE": 8, "PERSON_NAME": 6, "IP_ADDRESS": 5,
    "PASSPORT": 20, "DRIVERS_LICENSE": 18, "DATE": 3,
}

# ── Surface metadata ─────────────────────────────────────────────────
_SURFACES: list[SurfaceInfo] = [
    SurfaceInfo(
        surface="MCP",
        description="Model Context Protocol — intercepts tool calls and context injections between LLM and MCP servers.",
        supported_protocols=["MCP/1.0", "JSON-RPC 2.0", "SSE streaming"],
        integration_guide="Deploy the DataShield MCP proxy as a sidecar. Configure your MCP client to route through the proxy endpoint. All tool_call and tool_result messages are inspected for PII before forwarding.",
    ),
    SurfaceInfo(
        surface="A2A",
        description="Agent-to-Agent protocol — monitors inter-agent communication for PII leakage across trust boundaries.",
        supported_protocols=["A2A/1.0", "HTTP/2", "gRPC", "JSON Task envelope"],
        integration_guide="Register DataShield as an A2A middleware agent. Incoming and outgoing task messages are scanned. Configure trust boundaries per agent pair in policy YAML.",
    ),
    SurfaceInfo(
        surface="LLM_API",
        description="LLM API Gateway — inspects prompts and completions flowing to/from LLM providers (OpenAI, Anthropic, etc.).",
        supported_protocols=["REST/JSON", "OpenAI Chat Completions", "Anthropic Messages API", "SSE streaming"],
        integration_guide="Point your LLM SDK base_url to the DataShield gateway. Prompts are scanned inbound; completions are scanned outbound. Supports streaming interception with buffered entity detection.",
    ),
    SurfaceInfo(
        surface="RAG",
        description="Retrieval-Augmented Generation — scans retrieved context chunks before they enter the LLM prompt window.",
        supported_protocols=["Vector DB query/response", "REST/JSON", "LangChain Retriever interface"],
        integration_guide="Wrap your retriever with the DataShield RAG filter. Each retrieved chunk is scanned for PII. Chunks exceeding the policy threshold are redacted or blocked before prompt assembly.",
    ),
]


def _row_to_log(r) -> InterceptorLogOut:
    return InterceptorLogOut(
        id=r["id"], surface=r["surface"], direction=r["direction"],
        agent_id=r["agent_id"], payload_preview=r["payload_preview"],
        entities_found=r["entities_found"], action_taken=r["action_taken"],
        latency_ms=r["latency_ms"], timestamp=r["timestamp"])


def _compute_risk_score(detections: list) -> float:
    if not detections:
        return 0.0
    raw = sum(_SEVERITY_WEIGHTS.get(d.entity_type, 5) for d in detections)
    return min(round(raw, 1), 100.0)


def _sanitize_payload(text: str, detections: list) -> str:
    result = list(text)
    for d in sorted(detections, key=lambda x: x.start, reverse=True):
        replacement = f"[{d.entity_type}]"
        result[d.start:d.end] = list(replacement)
    return "".join(result)


def _determine_action(detections: list, risk_score: float) -> str:
    if risk_score >= 60:
        return "BLOCKED"
    if detections:
        return "TOKENIZED"
    return "PASSED"


def _build_recommendation(action: str, risk_score: float, count: int) -> str:
    if action == "BLOCKED":
        return f"High-risk payload blocked ({count} entities, risk {risk_score}). Review agent permissions and apply stricter policy rules."
    if action == "TOKENIZED":
        return f"Payload tokenized ({count} entities, risk {risk_score}). Entities replaced with vault tokens. Safe to forward."
    return "No sensitive entities detected. Payload passed without modification."


async def _load_policy_rules(policy_id: str) -> list[dict]:
    """Parse policy YAML rules from DB. Returns list of {entity_type, action}."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT yaml_content FROM policies WHERE policy_id=?", (policy_id,))
        row = await cur.fetchone()
        if not row:
            return []
        rules = []
        for line in row["yaml_content"].split("\n"):
            line = line.strip()
            if line.startswith("- entity_type:"):
                rules.append({"entity_type": line.split(":")[1].strip()})
            elif line.startswith("action:") and rules:
                rules[-1]["action"] = line.split(":")[1].strip()
        return rules
    finally:
        await db.close()


async def _run_simulation(surface: str, payload: str, agent_id: str | None,
                          agent_role: str | None, policy_id: str | None) -> InterceptSimulateResponse:
    t0 = time.monotonic()
    detections = detect(payload)
    elapsed_ms = round((time.monotonic() - t0) * 1000, 1)

    entities = [DetectedEntity(entity_type=d.entity_type, original_text=d.text,
                               start=d.start, end=d.end, confidence=d.confidence) for d in detections]
    risk_score = _compute_risk_score(detections)

    # Apply policy rules if provided
    policy_decisions: list[PolicyDecision] = []
    if policy_id:
        rules = await _load_policy_rules(policy_id)
        entity_types_found = {d.entity_type for d in detections}
        for rule in rules:
            if rule["entity_type"] in entity_types_found:
                policy_decisions.append(PolicyDecision(
                    entity_type=rule["entity_type"],
                    action=rule.get("action", "LOG"),
                    rule_source=policy_id,
                ))
        # Escalate risk if policy has REDACT rules that matched
        if any(pd.action == "REDACT" for pd in policy_decisions):
            risk_score = min(risk_score + 15, 100.0)

    action = _determine_action(detections, risk_score)
    sanitized = _sanitize_payload(payload, detections) if detections else payload
    vault_ref = f"vault://{uuid.uuid4().hex[:12]}" if action == "TOKENIZED" else None
    recommendation = _build_recommendation(action, risk_score, len(detections))

    # Log to DB
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO interceptor_logs (surface,direction,agent_id,payload_preview,entities_found,action_taken,latency_ms,timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (surface, "INBOUND", agent_id or "unknown", payload[:200], len(detections), action, elapsed_ms, datetime.utcnow().isoformat()))
        await db.commit()
    finally:
        await db.close()

    return InterceptSimulateResponse(
        surface=surface,
        entities_found=len(detections),
        entities_detected=entities,
        policy_decisions=policy_decisions,
        action_taken=action,
        sanitized_payload=sanitized,
        vault_ref=vault_ref,
        latency_ms=elapsed_ms,
        risk_score=risk_score,
        recommendation=recommendation,
    )


# ── GET /api/interceptor/logs ────────────────────────────────────────

@router.get("/logs", response_model=list[InterceptorLogOut])
async def list_logs(
    surface: str | None = None,
    direction: str | None = None,
    agent_id: str | None = None,
    action_taken: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    db = await get_db()
    try:
        clauses, params = [], []
        if surface:
            clauses.append("surface=?"); params.append(surface)
        if direction:
            clauses.append("direction=?"); params.append(direction)
        if agent_id:
            clauses.append("agent_id=?"); params.append(agent_id)
        if action_taken:
            clauses.append("action_taken=?"); params.append(action_taken)
        if date_from:
            clauses.append("timestamp>=?"); params.append(date_from)
        if date_to:
            clauses.append("timestamp<=?"); params.append(date_to)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params += [limit, offset]
        cur = await db.execute(
            f"SELECT * FROM interceptor_logs {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?", params)
        return [_row_to_log(r) for r in await cur.fetchall()]
    finally:
        await db.close()


# ── POST /api/interceptor/simulate ───────────────────────────────────

@router.post("/simulate", response_model=InterceptSimulateResponse)
async def simulate_interception(req: InterceptSimulateRequest):
    return await _run_simulation(req.surface, req.payload, req.agent_id, req.agent_role, req.policy_id)


# ── POST /api/interceptor/batch ──────────────────────────────────────

@router.post("/batch", response_model=InterceptBatchResponse)
async def batch_simulate(req: InterceptBatchRequest):
    if not req.payloads:
        raise HTTPException(status_code=422, detail="payloads list must not be empty")
    if len(req.payloads) > 100:
        raise HTTPException(status_code=422, detail="Maximum 100 payloads per batch")

    results: list[InterceptSimulateResponse] = []
    for payload in req.payloads:
        r = await _run_simulation(req.surface, payload, req.agent_id, req.agent_role, req.policy_id)
        results.append(r)

    return InterceptBatchResponse(
        results=results,
        total_payloads=len(results),
        total_entities=sum(r.entities_found for r in results),
        total_blocked=sum(1 for r in results if r.action_taken == "BLOCKED"),
        total_latency_ms=round(sum(r.latency_ms for r in results), 1),
    )


# ── GET /api/interceptor/stats ───────────────────────────────────────

@router.get("/stats", response_model=InterceptorStats)
async def interceptor_stats():
    db = await get_db()
    try:
        cur = await db.execute("SELECT count(*) as c FROM interceptor_logs")
        total = (await cur.fetchone())["c"]

        cur2 = await db.execute("SELECT surface, count(*) as c FROM interceptor_logs GROUP BY surface")
        by_surface = {r["surface"]: r["c"] for r in await cur2.fetchall()}

        cur3 = await db.execute("SELECT action_taken, count(*) as c FROM interceptor_logs GROUP BY action_taken")
        by_action = {r["action_taken"]: r["c"] for r in await cur3.fetchall()}

        cur4 = await db.execute("SELECT agent_id, count(*) as c FROM interceptor_logs WHERE agent_id IS NOT NULL GROUP BY agent_id")
        by_agent = {r["agent_id"]: r["c"] for r in await cur4.fetchall()}

        cur5 = await db.execute(
            "SELECT substr(timestamp,1,13) as hour, count(*) as c FROM interceptor_logs GROUP BY hour ORDER BY hour DESC LIMIT 24")
        by_hour = [{"hour": r["hour"], "count": r["c"]} for r in await cur5.fetchall()]

        cur6 = await db.execute("SELECT avg(latency_ms) as a FROM interceptor_logs")
        avg_lat = (await cur6.fetchone())["a"] or 0.0

        return InterceptorStats(
            total=total,
            by_surface=by_surface,
            by_action=by_action,
            by_agent=by_agent,
            by_hour=by_hour,
            total_blocked=by_action.get("BLOCKED", 0),
            total_tokenized=by_action.get("TOKENIZED", 0),
            total_passed=by_action.get("PASSED", 0) + by_action.get("LOGGED", 0),
            avg_latency=round(avg_lat, 1),
        )
    finally:
        await db.close()


# ── GET /api/interceptor/surfaces ────────────────────────────────────

@router.get("/surfaces", response_model=list[SurfaceInfo])
async def list_surfaces():
    return _SURFACES
