"""SQLite database: table creation + realistic seed data."""
from __future__ import annotations
import json, hashlib, os, random, uuid
from datetime import datetime, timedelta
from pathlib import Path

import aiosqlite

DB_PATH = Path(__file__).resolve().parent.parent.parent / "datashield.db"

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    agent_id TEXT,
    policy_id TEXT,
    entities_protected INTEGER DEFAULT 0,
    tokens_generated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS entities_detected (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    entity_type TEXT NOT NULL,
    original_text TEXT NOT NULL,
    token TEXT NOT NULL,
    confidence REAL NOT NULL,
    action TEXT NOT NULL DEFAULT 'TOKENIZE',
    detected_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    yaml_content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    compliance_packs TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    session_id INTEGER,
    agent_id TEXT,
    agent_role TEXT,
    policy_id TEXT,
    entities_json TEXT,
    latency_ms REAL,
    source_ip TEXT,
    target_service TEXT,
    timestamp TEXT NOT NULL,
    hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS interceptor_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    surface TEXT NOT NULL,
    direction TEXT NOT NULL,
    agent_id TEXT,
    payload_preview TEXT,
    entities_found INTEGER DEFAULT 0,
    action_taken TEXT NOT NULL,
    latency_ms REAL DEFAULT 0,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT NOT NULL,
    controls_total INTEGER NOT NULL,
    controls_passing INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_assessed TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    agent_id TEXT,
    description TEXT NOT NULL,
    detection_signal TEXT NOT NULL,
    response_action TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_ttl INTEGER NOT NULL DEFAULT 1800,
    session_timeout INTEGER NOT NULL DEFAULT 3600,
    confidence_threshold REAL NOT NULL DEFAULT 0.75,
    enabled_entity_types TEXT NOT NULL DEFAULT '["SSN","EMAIL","PHONE","CREDIT_CARD","IP_ADDRESS","PERSON_NAME","IBAN","API_KEY","DATE","PASSPORT","DRIVERS_LICENSE"]',
    notification_email_enabled INTEGER NOT NULL DEFAULT 0,
    notification_slack_enabled INTEGER NOT NULL DEFAULT 0,
    notification_siem_enabled INTEGER NOT NULL DEFAULT 0,
    notification_webhook_enabled INTEGER NOT NULL DEFAULT 0,
    webhook_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '[]',
    is_default INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_code TEXT NOT NULL,
    control_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'NOT_ASSESSED',
    evidence_type TEXT NOT NULL DEFAULT 'AUDIT_TRAIL',
    last_checked TEXT,
    remediation_hint TEXT DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'MEDIUM',
    FOREIGN KEY (framework_code) REFERENCES compliance_frameworks(code)
);
"""


async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(str(DB_PATH))
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    db = await get_db()
    try:
        await db.executescript(_CREATE_TABLES)
        await db.commit()
        # Check if already seeded
        cur = await db.execute("SELECT count(*) FROM policies")
        row = await cur.fetchone()
        if row[0] == 0:
            await _seed(db)
        # Always ensure settings and agent_roles are seeded (for existing DBs)
        await _seed_settings_and_roles(db)
    finally:
        await db.close()


async def _seed_settings_and_roles(db: aiosqlite.Connection):
    """Seed settings and agent_roles if empty (idempotent, runs on every startup)."""
    cur = await db.execute("SELECT count(*) FROM settings")
    row = await cur.fetchone()
    if row[0] == 0:
        await db.execute(
            "INSERT INTO settings (vault_ttl, session_timeout, confidence_threshold, enabled_entity_types, notification_email_enabled, notification_slack_enabled, notification_siem_enabled, notification_webhook_enabled, webhook_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1800, 3600, 0.75,
             '["SSN","EMAIL","PHONE","CREDIT_CARD","IP_ADDRESS","PERSON_NAME","IBAN","API_KEY","DATE","PASSPORT","DRIVERS_LICENSE"]',
             0, 0, 0, 0, ""))

    cur = await db.execute("SELECT count(*) FROM agent_roles")
    row = await cur.fetchone()
    if row[0] == 0:
        for rname, rdesc, perms, is_def in [
            ("data-processor", "Processes and transforms data — can tokenize and pseudonymize", '["scan","tokenize","pseudonymize","restore"]', 1),
            ("auditor", "Read-only audit access — can view sessions and logs", '["scan","view_sessions","view_audit"]', 1),
            ("admin", "Full administrative access — all operations", '["scan","tokenize","pseudonymize","restore","manage_policies","manage_settings","view_audit","purge_sessions"]', 1),
            ("analyst", "Data analyst — can scan and view generalized data", '["scan","generalize","view_sessions"]', 1),
            ("read-only", "Minimal access — scan only with redaction", '["scan"]', 1),
        ]:
            await db.execute(
                "INSERT INTO agent_roles (role_name, description, permissions, is_default) VALUES (?, ?, ?, ?)",
                (rname, rdesc, perms, is_def))
    await db.commit()


# ── Seed helpers ──────────────────────────────────────────────────────

_NOW = datetime.utcnow()
_AGENTS = ["agent-kyc-01", "agent-claims-02", "agent-onboard-03", "agent-fraud-04",
           "agent-rag-05", "agent-support-06", "agent-billing-07", "agent-audit-08"]
_ROLES = ["data-processor", "auditor", "admin", "analyst", "read-only"]
_ENTITY_TYPES = ["SSN", "EMAIL", "PHONE", "CREDIT_CARD", "IP_ADDRESS", "PERSON_NAME",
                 "IBAN", "API_KEY", "DATE", "PASSPORT", "DRIVERS_LICENSE"]
_EVENT_TYPES = ["ENTITY_PROTECTED", "VAULT_WRITE", "VAULT_READ", "POLICY_VIOLATION", "SEMANTIC_BLOCK"]
_SURFACES = ["MCP", "A2A", "LLM_API", "RAG"]
_THREAT_TYPES = ["UNCONTROLLED_RAG", "PRIVILEGE_ESCALATION", "SALAMI_SLICING", "PROMPT_INJECTION", "OVERBROAD_API"]
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_ACTIONS = ["REDACT", "TOKENIZE", "MASK", "BLOCK", "LOG"]

_SAMPLE_ENTITIES = {
    "SSN": ["123-45-6789", "987-65-4321", "456-78-9012", "321-54-9876"],
    "EMAIL": ["john.doe@acmebank.com", "mary.patel@healthsys.org", "carlos.reyes@fintech.io", "jane.wu@insure.co"],
    "PHONE": ["(212) 555-0147", "+1 415-555-0198", "(312) 555-0234", "(646) 555-0312"],
    "CREDIT_CARD": ["4111-1111-1111-1111", "5500-0000-0000-0004", "3714-496353-98431"],
    "IP_ADDRESS": ["192.168.1.45", "10.0.3.201", "172.16.0.99", "203.0.113.42"],
    "PERSON_NAME": ["Dr. Sarah Mitchell", "Mr. James Rodriguez", "Mrs. Priya Sharma", "Ms. Elena Voronova"],
    "IBAN": ["DE89370400440532013000", "GB29NWBK60161331926819", "FR7630006000011234567890189"],
    "API_KEY": ["sk-proj-abc123def456ghi789", "AKIAIOSFODNN7EXAMPLE"],
    "DATE": ["03/15/2025", "2025-01-22", "12/31/2024"],
    "PASSPORT": ["AB1234567", "C98765432"],
    "DRIVERS_LICENSE": ["D1234 5678 90123"],
}


async def _seed(db: aiosqlite.Connection):
    # 1. Policies
    policies = [
        ("pol-bfsi-prod", "BFSI Production", "Production policy for banking/financial services - strict PII handling",
         "version: '1.0'\nrules:\n  - entity_type: SSN\n    action: REDACT\n  - entity_type: CREDIT_CARD\n    action: REDACT\n  - entity_type: EMAIL\n    action: TOKENIZE\n  - entity_type: PHONE\n    action: TOKENIZE\n  - entity_type: IBAN\n    action: REDACT\n  - entity_type: PERSON_NAME\n    action: TOKENIZE\nretention_days: 90\naudit: true",
         "ACTIVE", '["PCI-DSS","SOX","GDPR"]'),
        ("pol-healthcare", "Healthcare HIPAA", "HIPAA-compliant policy for healthcare data processing",
         "version: '1.0'\nrules:\n  - entity_type: SSN\n    action: REDACT\n  - entity_type: EMAIL\n    action: TOKENIZE\n  - entity_type: PHONE\n    action: MASK\n  - entity_type: PERSON_NAME\n    action: REDACT\n  - entity_type: DATE\n    action: MASK\n    roles: [data-processor]\nretention_days: 365\naudit: true",
         "ACTIVE", '["HIPAA","ISO-27701"]'),
        ("pol-pci-dss", "PCI-DSS Cardholder", "Cardholder data environment protection",
         "version: '1.0'\nrules:\n  - entity_type: CREDIT_CARD\n    action: REDACT\n  - entity_type: IBAN\n    action: REDACT\n  - entity_type: API_KEY\n    action: REDACT\nretention_days: 30\naudit: true",
         "ACTIVE", '["PCI-DSS"]'),
        ("pol-gdpr-default", "GDPR Default", "Default GDPR-compliant data handling for EU operations",
         "version: '1.0'\nrules:\n  - entity_type: EMAIL\n    action: TOKENIZE\n  - entity_type: PHONE\n    action: TOKENIZE\n  - entity_type: PERSON_NAME\n    action: TOKENIZE\n  - entity_type: IP_ADDRESS\n    action: MASK\n  - entity_type: SSN\n    action: REDACT\nretention_days: 180\naudit: true\nright_to_erasure: true",
         "ACTIVE", '["GDPR","CCPA"]'),
        ("pol-internal-dev", "Internal Dev/Test", "Relaxed policy for development and testing environments",
         "version: '1.0'\nrules:\n  - entity_type: SSN\n    action: TOKENIZE\n  - entity_type: CREDIT_CARD\n    action: TOKENIZE\n  - entity_type: EMAIL\n    action: PASS\n  - entity_type: PHONE\n    action: PASS\nretention_days: 7\naudit: false",
         "DRAFT", '[]'),
    ]
    ts = (_NOW - timedelta(days=30)).isoformat()
    for pid, name, desc, yaml_c, status, packs in policies:
        await db.execute(
            "INSERT INTO policies (policy_id,name,description,yaml_content,status,compliance_packs,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (pid, name, desc, yaml_c, status, packs, ts, _NOW.isoformat()))

    # 2. Compliance frameworks
    frameworks = [
        ("GDPR", "General Data Protection Regulation", "EU data protection and privacy regulation", "Privacy", 99, 91, "COMPLIANT"),
        ("HIPAA", "Health Insurance Portability and Accountability Act", "US healthcare data protection standard", "Healthcare", 75, 68, "COMPLIANT"),
        ("PCI-DSS-4", "PCI DSS 4.0", "Payment card industry data security standard version 4.0", "Financial", 64, 55, "PARTIAL"),
        ("CCPA", "California Consumer Privacy Act / CPRA", "California privacy rights for consumers", "Privacy", 45, 41, "COMPLIANT"),
        ("SOX", "Sarbanes-Oxley Act", "Financial reporting and audit trail requirements", "Financial", 38, 30, "PARTIAL"),
        ("EU-AI-ACT", "EU AI Act", "European Union regulation on artificial intelligence systems", "AI Governance", 52, 34, "PARTIAL"),
        ("ISO-27701", "ISO 27701", "Privacy information management system extension to ISO 27001", "Privacy", 88, 82, "COMPLIANT"),
        ("FERPA", "Family Educational Rights and Privacy Act", "US student education records protection", "Education", 28, 22, "NON_COMPLIANT"),
    ]
    for code, name, desc, cat, total, passing, status in frameworks:
        st = "COMPLIANT" if passing / total > 0.85 else ("PARTIAL" if passing / total > 0.65 else "NON_COMPLIANT")
        await db.execute(
            "INSERT INTO compliance_frameworks (code,name,description,category,controls_total,controls_passing,status,last_assessed) VALUES (?,?,?,?,?,?,?,?)",
            (code, name, desc, cat, total, passing, status, (_NOW - timedelta(days=random.randint(1, 14))).isoformat()))

    # 3. Scan sessions
    session_ids = []
    policy_ids = [p[0] for p in policies]
    statuses_pool = ["ACTIVE"] * 12 + ["EXPIRED"] * 6 + ["PURGED"] * 2
    for i in range(20):
        created = _NOW - timedelta(hours=random.randint(1, 168))
        expires = created + timedelta(hours=24)
        status = statuses_pool[i]
        agent = random.choice(_AGENTS)
        pol = random.choice(policy_ids)
        ep = random.randint(2, 25)
        tg = ep
        name = f"scan-{created.strftime('%Y%m%d')}-{i+1:03d}"
        cur = await db.execute(
            "INSERT INTO scan_sessions (name,created_at,expires_at,status,agent_id,policy_id,entities_protected,tokens_generated) VALUES (?,?,?,?,?,?,?,?)",
            (name, created.isoformat(), expires.isoformat(), status, agent, pol, ep, tg))
        session_ids.append(cur.lastrowid)

    # 4. Entities detected (~100+)
    for sid in session_ids:
        count = random.randint(3, 10)
        for _ in range(count):
            etype = random.choice(_ENTITY_TYPES)
            orig = random.choice(_SAMPLE_ENTITIES.get(etype, ["[SAMPLE]"]))
            token = f"<<{etype}_{random.randint(1,99)}>>"
            conf = round(random.uniform(0.70, 0.99), 2)
            action = random.choice(_ACTIONS[:3])
            det_at = (_NOW - timedelta(hours=random.randint(0, 72))).isoformat()
            await db.execute(
                "INSERT INTO entities_detected (session_id,entity_type,original_text,token,confidence,action,detected_at) VALUES (?,?,?,?,?,?,?)",
                (sid, etype, orig, token, conf, action, det_at))

    # 5. Audit events (50, with hash chain)
    prev_hash = "0" * 64
    for i in range(50):
        eid = f"evt_{uuid.uuid4().hex[:10]}"
        etype = random.choice(_EVENT_TYPES)
        sid = random.choice(session_ids)
        agent = random.choice(_AGENTS)
        role = random.choice(_ROLES)
        pol = random.choice(policy_ids)
        ents = json.dumps([{"type": random.choice(_ENTITY_TYPES), "action": random.choice(_ACTIONS[:3])}])
        lat = round(random.uniform(1.2, 45.0), 1)
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        target = random.choice(["llm-gateway", "rag-retriever", "mcp-server", "a2a-broker", "vault-service"])
        ts = (_NOW - timedelta(minutes=random.randint(0, 2880))).isoformat()
        raw = f"{eid}{etype}{ts}{prev_hash}"
        cur_hash = hashlib.sha256(raw.encode()).hexdigest()
        await db.execute(
            "INSERT INTO audit_events (event_id,event_type,session_id,agent_id,agent_role,policy_id,entities_json,latency_ms,source_ip,target_service,timestamp,hash,prev_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, etype, sid, agent, role, pol, ents, lat, src_ip, target, ts, cur_hash, prev_hash))
        prev_hash = cur_hash

    # 6. Interceptor logs (30)
    for _ in range(30):
        surface = random.choice(_SURFACES)
        direction = random.choice(["INBOUND", "OUTBOUND"])
        agent = random.choice(_AGENTS)
        previews = [
            "Customer SSN is 123-45-6789 and email john@bank.com",
            "Process payment for card 4111-1111-1111-1111",
            "Patient Dr. Sarah Mitchell records from 03/15/2025",
            "API key sk-proj-abc123def456ghi789 found in payload",
            "Transfer to IBAN DE89370400440532013000 requested",
            "User IP 192.168.1.45 accessed sensitive endpoint",
        ]
        preview = random.choice(previews)
        ef = random.randint(1, 5)
        action = random.choice(["BLOCKED", "TOKENIZED", "LOGGED", "REDACTED"])
        lat = round(random.uniform(2.0, 35.0), 1)
        ts = (_NOW - timedelta(minutes=random.randint(0, 1440))).isoformat()
        await db.execute(
            "INSERT INTO interceptor_logs (surface,direction,agent_id,payload_preview,entities_found,action_taken,latency_ms,timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (surface, direction, agent, preview, ef, action, lat, ts))

    # 7. Threat events (15)
    threat_descriptions = {
        "UNCONTROLLED_RAG": ("RAG retriever returned PII from unscoped vector store", "Embedding similarity matched PII-laden chunk without scope filter", "Block retrieval, quarantine chunk"),
        "PRIVILEGE_ESCALATION": ("Agent attempted to access data beyond its assigned role", "Role-binding check failed: agent requested admin-scope data", "Deny access, flag agent for review"),
        "SALAMI_SLICING": ("Repeated micro-queries aggregating to full PII reconstruction", "Query pattern analysis detected incremental PII assembly over 12 requests", "Rate-limit agent, alert SOC"),
        "PROMPT_INJECTION": ("Injected prompt attempted to bypass data classification", "Prompt classifier detected instruction-override pattern", "Block request, log injection attempt"),
        "OVERBROAD_API": ("API call scope exceeded declared agent capabilities", "Capability manifest mismatch: agent declared read-only but issued write", "Reject API call, revoke token"),
    }
    for i in range(15):
        ttype = random.choice(_THREAT_TYPES)
        sev = random.choice(_SEVERITIES)
        agent = random.choice(_AGENTS)
        desc, signal, resp = threat_descriptions[ttype]
        status = random.choice(["BLOCKED", "BLOCKED", "FLAGGED", "RESOLVED"])
        ts = (_NOW - timedelta(hours=random.randint(0, 120))).isoformat()
        await db.execute(
            "INSERT INTO threat_events (threat_type,severity,agent_id,description,detection_signal,response_action,status,timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (ttype, sev, agent, desc, signal, resp, status, ts))

    # 8. Compliance controls (~75 total, 8-12 per framework)
    _controls = [
        # GDPR (10 controls)
        ("GDPR", "GDPR-5.1", "Data Minimization", "Art.5(1)(c) — Only collect data adequate, relevant, and limited to purpose", "PASS", "ENTITY_DETECTION", "Ensure detection engine flags over-collection of PII beyond stated purpose", "HIGH"),
        ("GDPR", "GDPR-25.1", "Privacy by Design", "Art.25 — Implement data protection by design and by default in all processing", "PASS", "POLICY_CONFIG", "Embed privacy controls in system architecture from inception", "HIGH"),
        ("GDPR", "GDPR-32.1", "Pseudonymization", "Art.32(1)(a) — Apply pseudonymization and encryption of personal data", "PASS", "VAULT_OPERATION", "Enable tokenization/pseudonymization in vault for all PII types", "CRITICAL"),
        ("GDPR", "GDPR-26.1", "Anonymization", "Rec.26 — Render data anonymous so data subject is no longer identifiable", "PASS", "VAULT_OPERATION", "Use irreversible anonymization where feasible; verify with re-identification tests", "HIGH"),
        ("GDPR", "GDPR-17.1", "Right to Erasure", "Art.17 — Erase personal data without undue delay upon request", "FAIL", "ERASURE_CAPABILITY", "Implement session purge and vault erasure endpoint; demonstrate deletion within 30 days", "CRITICAL"),
        ("GDPR", "GDPR-15.1", "Transparency", "Art.15 — Provide data subjects access to their personal data and processing info", "PASS", "AUDIT_TRAIL", "Maintain audit trail of all data access; provide export capability", "HIGH"),
        ("GDPR", "GDPR-33.1", "Breach Notification", "Art.33 — Notify supervisory authority within 72 hours of personal data breach", "PASS", "AUDIT_TRAIL", "Configure automated breach detection alerts with <72h SLA", "CRITICAL"),
        ("GDPR", "GDPR-6.1", "Lawful Basis", "Art.6 — Ensure lawful basis for each processing activity (consent, contract, etc.)", "PASS", "POLICY_CONFIG", "Document lawful basis in policy configuration for each data flow", "HIGH"),
        ("GDPR", "GDPR-35.1", "Impact Assessment", "Art.35 — Conduct DPIA for high-risk processing activities", "FAIL", "POLICY_CONFIG", "Run automated compliance assessment before deploying new data flows", "MEDIUM"),
        ("GDPR", "GDPR-44.1", "Cross-Border Transfer", "Art.44 — Restrict transfers of personal data to third countries without safeguards", "PASS", "POLICY_CONFIG", "Enforce geo-fencing rules in policy engine for data residency", "HIGH"),
        # HIPAA (10 controls)
        ("HIPAA", "HIPAA-SH.1", "Safe Harbor 18 Identifiers", "164.514(b)(2) — Remove all 18 HIPAA Safe Harbor identifiers from PHI", "PASS", "ENTITY_DETECTION", "Ensure detection engine covers all 18 identifier types (name, DOB, SSN, etc.)", "CRITICAL"),
        ("HIPAA", "HIPAA-ED.1", "Expert Determination", "164.514(b)(1) — Apply statistical/scientific methods to de-identify data", "FAIL", "ENTITY_DETECTION", "Implement k-anonymity or differential privacy for expert determination method", "HIGH"),
        ("HIPAA", "HIPAA-MN.1", "Minimum Necessary Standard", "164.502(b) — Limit PHI disclosure to minimum necessary for purpose", "PASS", "POLICY_CONFIG", "Configure role-based access policies restricting PHI fields per use case", "HIGH"),
        ("HIPAA", "HIPAA-BA.1", "Business Associate Agreements", "164.502(e) — Ensure BAAs cover all third-party data processors", "PASS", "POLICY_CONFIG", "Verify all agent integrations have documented BAA coverage", "HIGH"),
        ("HIPAA", "HIPAA-AC.1", "Audit Controls", "164.312(b) — Implement mechanisms to record and examine PHI access", "PASS", "AUDIT_TRAIL", "Maintain immutable hash-chain audit log for all PHI access events", "CRITICAL"),
        ("HIPAA", "HIPAA-AE.1", "Access Enforcement", "164.312(a)(1) — Allow access only to authorized persons/software", "PASS", "POLICY_CONFIG", "Enforce RBAC with agent role bindings for PHI access", "CRITICAL"),
        ("HIPAA", "HIPAA-TI.1", "Transmission Integrity", "164.312(e)(1) — Protect PHI during electronic transmission", "PASS", "VAULT_OPERATION", "Encrypt PHI in transit; tokenize before sending to external services", "HIGH"),
        ("HIPAA", "HIPAA-EP.1", "Emergency Access", "164.312(a)(2)(ii) — Establish procedures for obtaining PHI during emergency", "FAIL", "POLICY_CONFIG", "Define break-glass policy with audit logging for emergency PHI access", "MEDIUM"),
        ("HIPAA", "HIPAA-DI.1", "Data Integrity", "164.312(c)(1) — Protect PHI from improper alteration or destruction", "PASS", "AUDIT_TRAIL", "Use hash-chain verification to detect tampering of protected records", "HIGH"),
        ("HIPAA", "HIPAA-DP.1", "Disposal Procedures", "164.310(d)(2)(i) — Implement policies for final disposition of PHI", "PASS", "ERASURE_CAPABILITY", "Demonstrate secure purge of session data and vault entries", "HIGH"),
        # PCI DSS 4.0 (10 controls)
        ("PCI-DSS-4", "PCI-3.1", "Protect Stored Data", "Req.3 — Protect stored cardholder data via encryption, truncation, masking, or hashing", "PASS", "VAULT_OPERATION", "Tokenize or encrypt all stored cardholder data; verify no plaintext PAN in logs", "CRITICAL"),
        ("PCI-DSS-4", "PCI-6.1", "Secure Systems", "Req.6 — Develop and maintain secure systems and applications", "PASS", "POLICY_CONFIG", "Apply security patches; scan for vulnerabilities in data handling code", "HIGH"),
        ("PCI-DSS-4", "PCI-7.1", "Restrict Access", "Req.7 — Restrict access to cardholder data by business need to know", "PASS", "POLICY_CONFIG", "Enforce least-privilege agent roles; block unauthorized PCI data access", "CRITICAL"),
        ("PCI-DSS-4", "PCI-8.1", "Identify Users", "Req.8 — Identify and authenticate access to system components", "FAIL", "AUDIT_TRAIL", "Assign unique agent IDs; log all access with agent identification", "CRITICAL"),
        ("PCI-DSS-4", "PCI-10.1", "Track Access", "Req.10 — Track and monitor all access to network resources and cardholder data", "PASS", "AUDIT_TRAIL", "Maintain tamper-evident audit trail for all PCI data access", "CRITICAL"),
        ("PCI-DSS-4", "PCI-12.1", "Security Policy", "Req.12 — Maintain an information security policy for all personnel", "FAIL", "POLICY_CONFIG", "Document and enforce comprehensive security policy in policy engine", "HIGH"),
        ("PCI-DSS-4", "PCI-3.4", "Render PAN Unreadable", "Req.3.4 — Render PAN unreadable anywhere it is stored", "PASS", "VAULT_OPERATION", "Apply one-way hashing or tokenization to all stored PANs", "CRITICAL"),
        ("PCI-DSS-4", "PCI-4.1", "Encrypt Transmission", "Req.4 — Encrypt transmission of cardholder data across open networks", "PASS", "VAULT_OPERATION", "Tokenize cardholder data before any external API transmission", "HIGH"),
        ("PCI-DSS-4", "PCI-9.1", "Physical Access", "Req.9 — Restrict physical access to cardholder data", "PASS", "POLICY_CONFIG", "Enforce digital-only access controls; no plaintext exports permitted", "MEDIUM"),
        ("PCI-DSS-4", "PCI-11.1", "Security Testing", "Req.11 — Regularly test security systems and processes", "FAIL", "AUDIT_TRAIL", "Schedule periodic compliance assessments; run automated pen-test scans", "HIGH"),
        # CCPA (8 controls)
        ("CCPA", "CCPA-RTK.1", "Right to Know", "1798.100 — Consumer right to know what personal information is collected", "PASS", "AUDIT_TRAIL", "Provide data inventory endpoint listing all collected entity types per consumer", "HIGH"),
        ("CCPA", "CCPA-RTD.1", "Right to Delete", "1798.105 — Consumer right to request deletion of personal information", "PASS", "ERASURE_CAPABILITY", "Implement and test session purge + vault erasure for consumer data", "CRITICAL"),
        ("CCPA", "CCPA-OPT.1", "Right to Opt-Out", "1798.120 — Consumer right to opt-out of sale of personal information", "FAIL", "POLICY_CONFIG", "Add opt-out flag in policy engine; block data sharing when opted out", "CRITICAL"),
        ("CCPA", "CCPA-DM.1", "Data Minimization", "1798.100(c) — Collect only personal information reasonably necessary", "PASS", "ENTITY_DETECTION", "Configure detection engine to flag over-collection beyond stated purpose", "HIGH"),
        ("CCPA", "CCPA-SP.1", "Service Provider Requirements", "1798.140(v) — Ensure service providers meet CCPA obligations", "PASS", "POLICY_CONFIG", "Verify all downstream agent integrations comply with CCPA restrictions", "HIGH"),
        ("CCPA", "CCPA-ND.1", "Non-Discrimination", "1798.125 — No discrimination against consumers exercising privacy rights", "PASS", "POLICY_CONFIG", "Ensure data deletion does not degrade service quality", "MEDIUM"),
        ("CCPA", "CCPA-FN.1", "Financial Incentives", "1798.125(b) — Disclose financial incentives for data collection", "PASS", "AUDIT_TRAIL", "Log and disclose any value exchange for consumer data", "LOW"),
        ("CCPA", "CCPA-NM.1", "Notice at Collection", "1798.100(b) — Inform consumers at or before point of data collection", "FAIL", "POLICY_CONFIG", "Configure pre-collection disclosure in interceptor layer", "HIGH"),
        # SOX (8 controls)
        ("SOX", "SOX-302.1", "CEO/CFO Certification", "Section 302 — Officers certify accuracy of financial reports and internal controls", "PASS", "AUDIT_TRAIL", "Maintain comprehensive audit trail for all financial data access", "CRITICAL"),
        ("SOX", "SOX-404.1", "Internal Controls", "Section 404 — Establish and assess internal controls over financial reporting", "PASS", "POLICY_CONFIG", "Define and enforce data access policies for financial data", "CRITICAL"),
        ("SOX", "SOX-802.1", "Record Retention (7yr)", "Section 802 — Retain audit work papers and records for 7 years", "FAIL", "AUDIT_TRAIL", "Configure 7-year retention policy for financial audit events", "CRITICAL"),
        ("SOX", "SOX-AT.1", "Audit Trail Integrity", "Section 802 — Protect integrity of audit trails from alteration", "PASS", "AUDIT_TRAIL", "Use hash-chain verification for tamper-evident audit log", "CRITICAL"),
        ("SOX", "SOX-AC.1", "Access Controls", "Section 404 — Restrict access to financial systems to authorized personnel", "PASS", "POLICY_CONFIG", "Enforce role-based access for financial data processing agents", "HIGH"),
        ("SOX", "SOX-CM.1", "Change Management", "Section 404 — Document and control changes to financial data systems", "FAIL", "AUDIT_TRAIL", "Log all policy and configuration changes with approver identity", "HIGH"),
        ("SOX", "SOX-SE.1", "Segregation of Duties", "Section 404 — Prevent single agent from controlling entire financial process", "PASS", "POLICY_CONFIG", "Enforce multi-agent approval for financial data operations", "HIGH"),
        ("SOX", "SOX-RM.1", "Risk Management", "Section 302 — Identify and manage risks to financial reporting integrity", "PASS", "AUDIT_TRAIL", "Run automated risk scoring on all financial data flows", "MEDIUM"),
        # EU AI Act (8 controls)
        ("EU-AI-ACT", "EUAI-10.1", "Data Quality", "Art.10 — Ensure training, validation, and testing data meets quality criteria", "PASS", "ENTITY_DETECTION", "Scan all AI training data for PII contamination; enforce data quality thresholds", "CRITICAL"),
        ("EU-AI-ACT", "EUAI-13.1", "Transparency", "Art.13 — Design high-risk AI systems for sufficient transparency", "PASS", "AUDIT_TRAIL", "Log all AI system decisions with explainability metadata", "HIGH"),
        ("EU-AI-ACT", "EUAI-15.1", "Accuracy", "Art.15 — High-risk AI systems shall achieve appropriate levels of accuracy", "FAIL", "ENTITY_DETECTION", "Validate detection accuracy metrics meet >90% threshold", "HIGH"),
        ("EU-AI-ACT", "EUAI-52.1", "Disclosure", "Art.52 — Inform users they are interacting with an AI system", "FAIL", "POLICY_CONFIG", "Add AI interaction disclosure in all agent-facing surfaces", "MEDIUM"),
        ("EU-AI-ACT", "EUAI-RC.1", "Risk Classification", "Art.6 — Classify AI systems by risk level (unacceptable, high, limited, minimal)", "PASS", "POLICY_CONFIG", "Assign risk classification to each agent and data flow", "CRITICAL"),
        ("EU-AI-ACT", "EUAI-9.1", "Risk Management System", "Art.9 — Establish and maintain risk management system throughout AI lifecycle", "FAIL", "AUDIT_TRAIL", "Implement continuous risk monitoring for all AI agent operations", "HIGH"),
        ("EU-AI-ACT", "EUAI-12.1", "Record Keeping", "Art.12 — Enable automatic recording of events (logging) for high-risk AI", "PASS", "AUDIT_TRAIL", "Maintain comprehensive event logs for all high-risk AI operations", "HIGH"),
        ("EU-AI-ACT", "EUAI-14.1", "Human Oversight", "Art.14 — High-risk AI systems designed for effective human oversight", "FAIL", "POLICY_CONFIG", "Implement human-in-the-loop review for high-risk agent decisions", "CRITICAL"),
        # ISO 27701 (8 controls)
        ("ISO-27701", "ISO-PIM.1", "Privacy Information Mgmt", "Clause 5 — Establish PIMS integrated with organizational ISMS", "PASS", "POLICY_CONFIG", "Configure comprehensive privacy management policies in policy engine", "HIGH"),
        ("ISO-27701", "ISO-DPR.1", "Data Processing Records", "Clause 8.2 — Maintain records of PII processing activities", "PASS", "AUDIT_TRAIL", "Log all PII processing events with purpose and legal basis", "HIGH"),
        ("ISO-27701", "ISO-PL.1", "Purpose Limitation", "Clause 7.2.1 — Process PII only for identified and documented purposes", "PASS", "POLICY_CONFIG", "Enforce purpose limitation in policy rules per entity type", "CRITICAL"),
        ("ISO-27701", "ISO-CM.1", "Consent Management", "Clause 7.2.3 — Obtain and record consent for PII processing", "FAIL", "POLICY_CONFIG", "Implement consent tracking in session metadata", "CRITICAL"),
        ("ISO-27701", "ISO-BR.1", "Breach Response", "Clause 6.13 — Establish PII breach notification procedures", "PASS", "AUDIT_TRAIL", "Configure automated breach detection and notification workflow", "CRITICAL"),
        ("ISO-27701", "ISO-RA.1", "Rights of Access", "Clause 7.3.2 — Enable PII principals to access their data", "PASS", "AUDIT_TRAIL", "Provide session and entity lookup endpoints for data subject access", "HIGH"),
        ("ISO-27701", "ISO-TP.1", "Third-Party Processing", "Clause 8.5 — Manage PII transfers to third parties", "PASS", "POLICY_CONFIG", "Enforce tokenization before any third-party data transfer", "HIGH"),
        ("ISO-27701", "ISO-RT.1", "Retention Policies", "Clause 7.4.7 — Define and enforce PII retention periods", "FAIL", "POLICY_CONFIG", "Configure automatic session expiry and vault TTL per data category", "HIGH"),
        # FERPA (8 controls)
        ("FERPA", "FERPA-SR.1", "Student Records Protection", "99.3 — Protect education records from unauthorized disclosure", "PASS", "ENTITY_DETECTION", "Detect and protect student PII (name, DOB, student ID) in all data flows", "CRITICAL"),
        ("FERPA", "FERPA-DI.1", "Directory Information", "99.3 — Define and limit directory information disclosures", "FAIL", "POLICY_CONFIG", "Configure directory information categories with opt-out enforcement", "HIGH"),
        ("FERPA", "FERPA-LEI.1", "Legitimate Educational Interest", "99.31(a) — Limit disclosures to officials with legitimate educational interest", "PASS", "POLICY_CONFIG", "Enforce role-based access restricting student data to authorized agents", "HIGH"),
        ("FERPA", "FERPA-AN.1", "Annual Notification", "99.7 — Notify parents/students annually of their FERPA rights", "FAIL", "POLICY_CONFIG", "Schedule automated annual notification workflow", "MEDIUM"),
        ("FERPA", "FERPA-AR.1", "Access and Review", "99.10 — Allow parents/students to inspect and review education records", "FAIL", "AUDIT_TRAIL", "Provide data export and review endpoints for record subjects", "HIGH"),
        ("FERPA", "FERPA-AM.1", "Amendment Rights", "99.20 — Allow parents/students to seek amendment of records", "FAIL", "POLICY_CONFIG", "Implement record amendment request and approval workflow", "MEDIUM"),
        ("FERPA", "FERPA-CL.1", "Complaint Filing", "99.63 — Maintain process for FERPA complaints", "PASS", "AUDIT_TRAIL", "Log and track all FERPA-related complaints and resolutions", "LOW"),
        ("FERPA", "FERPA-EX.1", "Exceptions Management", "99.31 — Document and manage all exceptions to consent requirements", "FAIL", "POLICY_CONFIG", "Configure exception rules with mandatory documentation and audit", "HIGH"),
    ]
    checked_time = (_NOW - timedelta(days=random.randint(1, 14))).isoformat()
    for fw_code, ctrl_id, name, desc, status, evidence, hint, severity in _controls:
        await db.execute(
            "INSERT INTO compliance_controls (framework_code,control_id,name,description,status,evidence_type,last_checked,remediation_hint,severity) VALUES (?,?,?,?,?,?,?,?,?)",
            (fw_code, ctrl_id, name, desc, status, evidence, checked_time, hint, severity))

    # 9. Settings (singleton row)
    cur = await db.execute("SELECT count(*) FROM settings")
    row = await cur.fetchone()
    if row[0] == 0:
        await db.execute(
            "INSERT INTO settings (vault_ttl, session_timeout, confidence_threshold, enabled_entity_types, notification_email_enabled, notification_slack_enabled, notification_siem_enabled, notification_webhook_enabled, webhook_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1800, 3600, 0.75,
             '["SSN","EMAIL","PHONE","CREDIT_CARD","IP_ADDRESS","PERSON_NAME","IBAN","API_KEY","DATE","PASSPORT","DRIVERS_LICENSE"]',
             0, 0, 0, 0, ""))

    # 9. Agent roles
    cur = await db.execute("SELECT count(*) FROM agent_roles")
    row = await cur.fetchone()
    if row[0] == 0:
        agent_roles = [
            ("data-processor", "Processes and transforms data — can tokenize and pseudonymize", '["scan","tokenize","pseudonymize","restore"]', 1),
            ("auditor", "Read-only audit access — can view sessions and logs", '["scan","view_sessions","view_audit"]', 1),
            ("admin", "Full administrative access — all operations", '["scan","tokenize","pseudonymize","restore","manage_policies","manage_settings","view_audit","purge_sessions"]', 1),
            ("analyst", "Data analyst — can scan and view generalized data", '["scan","generalize","view_sessions"]', 1),
            ("read-only", "Minimal access — scan only with redaction", '["scan"]', 1),
        ]
        for rname, rdesc, perms, is_def in agent_roles:
            await db.execute(
                "INSERT INTO agent_roles (role_name, description, permissions, is_default) VALUES (?, ?, ?, ?)",
                (rname, rdesc, perms, is_def))

    await db.commit()
