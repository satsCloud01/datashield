from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ── Scan / Protect / Restore ──────────────────────────────────────────

class ScanRequest(BaseModel):
    text: str
    session_name: Optional[str] = None
    agent_id: Optional[str] = None
    policy_id: Optional[str] = None

class DetectedEntity(BaseModel):
    entity_type: str
    original_text: str
    start: int
    end: int
    confidence: float

class ScanResponse(BaseModel):
    session_id: int
    entities: list[DetectedEntity]
    count: int

class ProtectRequest(BaseModel):
    text: str
    session_name: Optional[str] = None
    agent_id: Optional[str] = None
    policy_id: Optional[str] = None

class ProtectResponse(BaseModel):
    session_id: int
    sanitized_text: str
    vault_ref: str
    entities_protected: int
    tokens_generated: int

class RestoreRequest(BaseModel):
    vault_ref: str

class RestoreResponse(BaseModel):
    original_text: str
    entities_restored: int


# ── Sessions ──────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    name: str
    agent_id: Optional[str] = None
    policy_id: Optional[str] = None

class SessionOut(BaseModel):
    id: int
    name: str
    created_at: str
    expires_at: Optional[str] = None
    status: str
    agent_id: Optional[str] = None
    policy_id: Optional[str] = None
    entities_protected: int = 0
    tokens_generated: int = 0

class EntityOut(BaseModel):
    id: int
    session_id: int
    entity_type: str
    original_text: str
    token: str
    confidence: float
    action: str
    detected_at: str

class SessionDetail(SessionOut):
    entities: list[EntityOut] = []


# ── Policies ──────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    policy_id: str
    name: str
    description: Optional[str] = ""
    yaml_content: str
    status: str = "DRAFT"
    compliance_packs: list[str] = []

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    yaml_content: Optional[str] = None
    status: Optional[str] = None
    compliance_packs: Optional[list[str]] = None

class PolicyOut(BaseModel):
    id: int
    policy_id: str
    name: str
    description: str
    yaml_content: str
    status: str
    compliance_packs: list[str]
    created_at: str
    updated_at: str


# ── Audit ─────────────────────────────────────────────────────────────

class AuditEventOut(BaseModel):
    id: int
    event_id: str
    event_type: str
    session_id: Optional[int] = None
    agent_id: Optional[str] = None
    agent_role: Optional[str] = None
    policy_id: Optional[str] = None
    entities_json: Optional[str] = None
    latency_ms: Optional[float] = None
    source_ip: Optional[str] = None
    target_service: Optional[str] = None
    timestamp: str
    hash: str
    prev_hash: str

class AuditEventDetail(AuditEventOut):
    prev_event_hash: Optional[str] = None
    next_event_hash: Optional[str] = None

class AuditStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_agent: dict[str, int] = {}
    by_hour: list[dict] = []
    by_entity_type: dict[str, int] = {}
    avg_latency: float = 0.0
    peak_hour: Optional[str] = None
    unique_agents: int = 0
    unique_sessions: int = 0

class AuditVerifyResponse(BaseModel):
    verified: bool
    total_events: int
    chain_length: int
    broken_links: list[dict] = []
    first_event: Optional[str] = None
    last_event: Optional[str] = None
    verification_time_ms: float

class AuditAgentSummary(BaseModel):
    agent_id: str
    event_count: int

class AuditSessionTrail(BaseModel):
    session_id: int
    events: list[AuditEventOut]


# ── Interceptor ───────────────────────────────────────────────────────

class InterceptorLogOut(BaseModel):
    id: int
    surface: str
    direction: str
    agent_id: Optional[str] = None
    payload_preview: Optional[str] = None
    entities_found: int
    action_taken: str
    latency_ms: float
    timestamp: str

class InterceptSimulateRequest(BaseModel):
    surface: str
    payload: str
    agent_id: Optional[str] = None
    agent_role: Optional[str] = None
    policy_id: Optional[str] = None

class PolicyDecision(BaseModel):
    entity_type: str
    action: str
    rule_source: str

class InterceptSimulateResponse(BaseModel):
    surface: str
    entities_found: int
    entities_detected: list[DetectedEntity]
    policy_decisions: list[PolicyDecision] = []
    action_taken: str
    sanitized_payload: str
    vault_ref: Optional[str] = None
    latency_ms: float
    risk_score: float
    recommendation: str

class InterceptBatchRequest(BaseModel):
    surface: str
    payloads: list[str]
    agent_id: Optional[str] = None
    agent_role: Optional[str] = None
    policy_id: Optional[str] = None

class InterceptBatchResponse(BaseModel):
    results: list[InterceptSimulateResponse]
    total_payloads: int
    total_entities: int
    total_blocked: int
    total_latency_ms: float

class SurfaceInfo(BaseModel):
    surface: str
    description: str
    supported_protocols: list[str]
    integration_guide: str

class InterceptorStats(BaseModel):
    total: int
    by_surface: dict[str, int]
    by_action: dict[str, int]
    by_agent: dict[str, int] = {}
    by_hour: list[dict] = []
    total_blocked: int = 0
    total_tokenized: int = 0
    total_passed: int = 0
    avg_latency: float = 0.0


# ── Compliance ────────────────────────────────────────────────────────

class ComplianceFrameworkOut(BaseModel):
    id: int
    code: str
    name: str
    description: str
    category: str
    controls_total: int
    controls_passing: int
    status: str
    last_assessed: str

class ComplianceControlOut(BaseModel):
    id: int
    framework_code: str
    control_id: str
    name: str
    description: str
    status: str  # PASS, FAIL, NOT_ASSESSED
    evidence_type: str
    last_checked: Optional[str] = None
    remediation_hint: str = ""
    severity: str = "MEDIUM"

class ComplianceFrameworkDetail(ComplianceFrameworkOut):
    controls_failing: int = 0
    controls: list[ComplianceControlOut] = []

class ComplianceGap(BaseModel):
    framework_code: str
    control_id: str
    name: str
    severity: str
    remediation_hint: str

class ComplianceSummary(BaseModel):
    overall_score: float
    frameworks_total: int
    compliant: int
    partial: int
    non_compliant: int
    controls_total: int = 0
    controls_passing: int = 0
    top_gaps: list[ComplianceGap] = []

class ComplianceAssessmentResult(BaseModel):
    framework_code: str
    status: str
    controls_total: int
    controls_passing: int
    controls_failing: int
    entity_coverage_pct: float
    entity_types_covered: list[str]
    entity_types_missing: list[str]
    vault_active: bool
    audit_trail_count: int
    findings: list[str]
    assessed_at: str

class ComplianceReport(BaseModel):
    generated_at: str
    overall_score: float
    frameworks: list[ComplianceFrameworkDetail]
    total_controls: int
    total_passing: int
    total_failing: int


# ── Threats ───────────────────────────────────────────────────────────

class ThreatEventOut(BaseModel):
    id: int
    threat_type: str
    severity: str
    agent_id: Optional[str] = None
    description: str
    detection_signal: str
    response_action: str
    status: str
    timestamp: str

class ThreatSimulateRequest(BaseModel):
    threat_type: str
    payload: str
    agent_id: Optional[str] = None
    agent_role: Optional[str] = None
    target_agent_id: Optional[str] = None
    context: Optional[str] = None

class ThreatSimulateResponse(BaseModel):
    threat_detected: bool
    threat_type: str
    severity: str
    risk_score: float
    detection_signals: list[str]
    response_action: str
    recommendation: str
    blocked: bool

class ThreatResolveRequest(BaseModel):
    resolution_note: str

class ThreatPatternDefinition(BaseModel):
    threat_type: str
    description: str
    detection_signals: list[str]
    response_actions: list[str]
    example_payloads: list[str]

class ThreatStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_status: dict[str, int] = {}
    by_agent: dict[str, int] = {}
    timeline: list[dict] = []
    total_blocked: int = 0
    total_flagged: int = 0
    total_resolved: int = 0
    risk_trend: list[dict] = []


# ── Dashboard ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_scans: int
    entities_protected: int
    active_sessions: int
    threats_blocked: int
    avg_latency_ms: float
    compliance_score: float

class TimelinePoint(BaseModel):
    hour: str
    count: int

class EntityDistribution(BaseModel):
    entity_type: str
    count: int


# ── Settings ─────────────────────────────────────────────────────────

class SettingsOut(BaseModel):
    vault_ttl: int
    session_timeout: int
    confidence_threshold: float
    enabled_entity_types: list[str]
    notification_email_enabled: bool
    notification_slack_enabled: bool
    notification_siem_enabled: bool
    notification_webhook_enabled: bool
    webhook_url: str

class SettingsUpdate(BaseModel):
    vault_ttl: Optional[int] = None
    session_timeout: Optional[int] = None
    confidence_threshold: Optional[float] = None
    enabled_entity_types: Optional[list[str]] = None
    notification_email_enabled: Optional[bool] = None
    notification_slack_enabled: Optional[bool] = None
    notification_siem_enabled: Optional[bool] = None
    notification_webhook_enabled: Optional[bool] = None
    webhook_url: Optional[str] = None


# ── Agent Roles ──────────────────────────────────────────────────────

class AgentRoleOut(BaseModel):
    id: int
    role_name: str
    description: str
    permissions: list[str]
    is_default: bool

class AgentRoleCreate(BaseModel):
    role_name: str
    description: str = ""
    permissions: list[str] = []
    is_default: bool = False
