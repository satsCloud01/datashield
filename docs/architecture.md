# DataShield AI — Architecture Documentation

> Version 1.0 · Last updated 2026-03-27

---

## Table of Contents

1. [C1 — System Context](#c1--system-context)
2. [C2 — Container Diagram](#c2--container-diagram)
3. [C3 — Component Diagrams](#c3--component-diagrams)
4. [C4 — Code Level](#c4--code-level)

---

## C1 — System Context

**DataShield AI** is an agentic data privacy infrastructure that sits between AI agents and LLM APIs, intercepting data flows to detect PII/PHI/PCI entities, tokenize sensitive values, enforce compliance policies, and maintain a tamper-evident audit trail.

```mermaid
graph TB
    subgraph External Actors
        AGENTS["AI Agents<br/>(MCP / A2A / LangGraph)"]
        LLM["LLM APIs<br/>(Anthropic / OpenAI / Gemini)"]
        ENTERPRISE["Enterprise Systems<br/>(CRM / EHR / Financial)"]
        SECURITY["Security Teams<br/>(SIEM / SOC)"]
    end

    DS["DataShield AI<br/>PII Detection · Tokenization<br/>Policy Enforcement · Audit Trail<br/>Threat Detection"]

    AGENTS -->|"Prompts & tool calls<br/>(intercept inbound)"| DS
    DS -->|"Sanitized prompts"| LLM
    LLM -->|"Completions<br/>(intercept outbound)"| DS
    DS -->|"Safe responses"| AGENTS
    ENTERPRISE -->|"Data context<br/>(RAG chunks, DB queries)"| DS
    DS -->|"Audit events<br/>Threat alerts"| SECURITY
```

### Key Interactions

| Actor | Direction | Description |
|-------|-----------|-------------|
| AI Agents | Inbound | Submit text for scanning, protection, and restoration via REST API |
| LLM APIs | Outbound | Receive sanitized prompts after PII tokenization |
| Enterprise Systems | Inbound | Provide data context (RAG chunks, database records) for interception |
| Security Teams | Outbound | Receive audit events, threat alerts, and compliance reports |

### Security Boundary

- No AI API keys are stored server-side. The system operates on text payloads only.
- All vault mappings are session-scoped and ephemeral by default.
- Audit trail uses SHA-256 hash chaining for tamper evidence.

---

## C2 — Container Diagram

```mermaid
graph TB
    subgraph DataShield AI
        FE["React Frontend<br/>(Vite + Tailwind)<br/>Port 5179"]
        API["FastAPI Backend<br/>(Python 3.12)<br/>Port 8007"]
        DB["SQLite Database<br/>(datashield.db)"]
        VAULT["Token Vault<br/>(In-memory Python)<br/>Session-scoped"]
        DETECT["Detection Engine<br/>(Regex + Context Scoring)<br/>57 entity types"]
        POLICY["Policy Engine<br/>(YAML + OPA-inspired)<br/>6 compliance packs"]
    end

    FE -->|"/api/* (Vite proxy)"| API
    API --> DB
    API --> VAULT
    API --> DETECT
    API --> POLICY
```

### Container Responsibilities

| Container | Technology | Responsibility |
|-----------|-----------|---------------|
| **Frontend SPA** | React 18, Vite, Tailwind CSS | 10 pages: Landing, Dashboard, Scanner, TokenVault, PolicyStudio, Interceptor, SemanticValidator, AuditTrail, Compliance, Settings |
| **API Server** | FastAPI, Python 3.12, Pydantic v2, aiosqlite | 9 routers + health endpoint, request validation, async database access |
| **SQLite Database** | aiosqlite, local file | 9 tables: scan_sessions, entities_detected, policies, audit_events, interceptor_logs, compliance_frameworks, compliance_controls, threat_events, settings, agent_roles |
| **Token Vault** | In-memory Python dataclasses | 6 obfuscation modes (REDACT, TOKENIZE, PSEUDONYMIZE, GENERALIZE, ENCRYPT, SYNTHESIZE), session lifecycle management |
| **Detection Engine** | Python regex, dataclasses, Enum | 4-stage pipeline: Regex matching, Context scoring, Validation (Luhn, etc.), Deduplication. 6 categories: PII, PHI, PCI, FINANCIAL, IP_CODE, CUSTOM |
| **Policy Engine** | PyYAML, dataclasses | YAML parsing, rule evaluation, conflict detection, compliance mapping, simulation |

---

## C3 — Component Diagrams

### C3a — Frontend Components

```mermaid
graph TB
    subgraph React Frontend
        APP["App.jsx<br/>(Router)"]
        LAYOUT["Layout<br/>(Sidebar + Content)"]

        LAND["Landing"]
        DASH["Dashboard"]
        SCAN["Scanner"]
        TV["TokenVault"]
        PS["PolicyStudio"]
        INT["Interceptor"]
        SV["SemanticValidator"]
        AT["AuditTrail"]
        COMP["Compliance"]
        SET["Settings"]
    end

    APP --> LAND
    APP --> LAYOUT
    LAYOUT --> DASH
    LAYOUT --> SCAN
    LAYOUT --> TV
    LAYOUT --> PS
    LAYOUT --> INT
    LAYOUT --> SV
    LAYOUT --> AT
    LAYOUT --> COMP
    LAYOUT --> SET
```

| Page | Responsibility |
|------|---------------|
| **Landing** | Product overview, feature highlights, CTA to dashboard |
| **Dashboard** | Aggregate stats: scans, entities protected, threats, compliance score, risk heatmap, timeline charts |
| **Scanner** | Text input with sample templates, real-time PII detection, entity annotation, batch scanning |
| **TokenVault** | Session management, entity-level token inspection, vault purge, session extend/expire |
| **PolicyStudio** | YAML policy editor, CRUD, compliance pack assignment, validation |
| **Interceptor** | Surface simulation (MCP, A2A, LLM_API, RAG), risk scoring, batch interception |
| **SemanticValidator** | Post-sanitization validation — verifies no PII remains in processed text |
| **AuditTrail** | Hash-chain viewer, event filtering, chain verification, export |
| **Compliance** | 8 framework dashboard, automated assessment, gap analysis, full report generation |
| **Settings** | Vault TTL, session timeout, confidence threshold, entity types toggle, notification config, agent role CRUD |

### C3b — Backend Components

```mermaid
graph TB
    subgraph API Routers
        R1["scanner<br/>/api/scan, /api/protect, /api/restore"]
        R2["sessions<br/>/api/sessions/*"]
        R3["policies<br/>/api/policies/*"]
        R4["audit<br/>/api/audit/*"]
        R5["interceptor<br/>/api/interceptor/*"]
        R6["compliance<br/>/api/compliance/*"]
        R7["threats<br/>/api/threats/*"]
        R8["dashboard<br/>/api/dashboard/*"]
        R9["settings<br/>/api/settings/*"]
    end

    subgraph Core Services
        DE["DetectionEngine<br/>4-stage pipeline<br/>57 entity types"]
        TV["TokenVault<br/>6 obfuscation modes<br/>Session lifecycle"]
        PE["PolicyEngine<br/>YAML validation<br/>Conflict detection"]
    end

    subgraph Data Layer
        DB["SQLite (aiosqlite)<br/>9 tables"]
    end

    R1 --> DE
    R1 --> TV
    R5 --> DE
    R3 --> PE
    R7 --> DE
    R1 --> DB
    R2 --> DB
    R3 --> DB
    R4 --> DB
    R5 --> DB
    R6 --> DB
    R7 --> DB
    R8 --> DB
    R9 --> DB
```

### Router Summary

| Router | Prefix | Endpoints | Core Responsibility |
|--------|--------|-----------|-------------------|
| scanner | `/api` | 7 | Scan, protect (tokenize), restore, batch scan, validate, entity registry, samples |
| sessions | `/api/sessions` | 6 | Session CRUD, entity listing, audit trail per session, extend, purge |
| policies | `/api/policies` | 4 | Policy CRUD with YAML validation |
| audit | `/api/audit` | 7 | Event listing, detail, stats, hash-chain verification, export, agent summary, session trail |
| interceptor | `/api/interceptor` | 5 | Logs, simulation, batch simulation, stats, surface metadata |
| compliance | `/api/compliance` | 6 | Frameworks, summary, gaps, report, framework detail, automated assessment |
| threats | `/api/threats` | 6 | Threat listing, simulation, stats, patterns, detail, resolve |
| dashboard | `/api/dashboard` | 7 | Stats, timeline, entity distribution, threat summary, agent activity, top entities, surface activity, risk heatmap |
| settings | `/api/settings` | 5 | Settings GET/PUT, agent role CRUD (list, create, delete) |

---

## C4 — Code Level

### C4a — Detection Engine Pipeline

```mermaid
graph LR
    INPUT["Raw Text"] --> STAGE1["Stage 1<br/>Regex Matching<br/>57 patterns"]
    STAGE1 --> STAGE2["Stage 2<br/>Context Scoring<br/>Proximity analysis"]
    STAGE2 --> STAGE3["Stage 3<br/>Validation<br/>Luhn, checksum, format"]
    STAGE3 --> STAGE4["Stage 4<br/>Deduplication<br/>Overlap resolution"]
    STAGE4 --> OUTPUT["Detection[]<br/>entity_type, text, start, end,<br/>confidence, category, risk_level"]
```

**Key Data Structures:**

```python
class Category(str, Enum):
    PII = "PII"          # SSN, EMAIL, PHONE, PERSON_NAME, IP_ADDRESS, PASSPORT, DRIVERS_LICENSE
    PHI = "PHI"          # DATE (medical context)
    PCI = "PCI"          # CREDIT_CARD
    FINANCIAL = "FINANCIAL"  # IBAN
    IP_CODE = "IP_CODE"  # API_KEY
    CUSTOM = "CUSTOM"

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"  # SSN, CREDIT_CARD, IBAN, API_KEY, PASSPORT, DRIVERS_LICENSE
    HIGH = "HIGH"          # EMAIL, PHONE, PERSON_NAME
    MEDIUM = "MEDIUM"      # IP_ADDRESS, DATE
    LOW = "LOW"
```

**Entity-to-Regulation Mapping (11 core types):**

| Entity Type | Category | Risk Level | Regulatory Basis | Default Action |
|-------------|----------|-----------|-----------------|----------------|
| SSN | PII | CRITICAL | GDPR Art.87, CCPA, HIPAA | REDACT |
| EMAIL | PII | HIGH | GDPR Art.4(1), CCPA 1798.140(o) | TOKENIZE |
| PHONE | PII | HIGH | GDPR Art.4(1), CCPA | TOKENIZE |
| CREDIT_CARD | PCI | CRITICAL | PCI DSS Req.3, GDPR Art.4(1) | REDACT |
| IP_ADDRESS | PII | MEDIUM | GDPR Rec.30, CCPA 1798.140(o) | MASK |
| PERSON_NAME | PII | HIGH | GDPR Art.4(1), HIPAA 164.514 | TOKENIZE |
| IBAN | FINANCIAL | CRITICAL | PCI DSS, GDPR Art.4(1), SOX | REDACT |
| API_KEY | IP_CODE | CRITICAL | SOX Section 302, Internal Policy | REDACT |
| DATE | PHI | MEDIUM | HIPAA 164.514(b)(2)(i) | GENERALIZE |
| PASSPORT | PII | CRITICAL | GDPR Art.87, CCPA | REDACT |
| DRIVERS_LICENSE | PII | CRITICAL | GDPR Art.87, CCPA, HIPAA | REDACT |

### C4b — Token Vault Lifecycle

```mermaid
stateDiagram-v2
    [*] --> CREATED: create_session()
    CREATED --> ACTIVE: First tokenize()
    ACTIVE --> ACTIVE: tokenize() / restore()
    ACTIVE --> EXPIRED: TTL exceeded
    ACTIVE --> PURGED: purge_session()
    EXPIRED --> PURGED: purge_session()
    PURGED --> [*]
```

**6 Obfuscation Modes:**

| Mode | Behavior | Reversible |
|------|----------|-----------|
| REDACT | Replace with `[REDACTED]` | No |
| TOKENIZE | Replace with vault token `<<TYPE_uuid>>` | Yes |
| PSEUDONYMIZE | Replace with consistent fake value | Yes (via vault) |
| GENERALIZE | Replace with category label (e.g., date -> "2020s") | Partial |
| ENCRYPT | Base64 + hash-based obfuscation | Yes (via vault) |
| SYNTHESIZE | Generate synthetic replacement value | No |

### C4c — Policy Engine Evaluation

```mermaid
graph TB
    YAML["YAML Policy Document"] --> PARSE["Parse & Validate<br/>(yaml.safe_load)"]
    PARSE --> RULES["Extract Rules<br/>{entity_type, action}"]
    RULES --> EVAL["Evaluate Against<br/>Detected Entities"]
    EVAL --> DECISION["PolicyDecision<br/>entity_type, action, reason,<br/>compliance_refs, overridden_by"]
    EVAL --> CONFLICT["ConflictDetection<br/>Overlapping rules"]
```

**Policy Decision Actions:** REDACT, TOKENIZE, PSEUDONYMIZE, GENERALIZE, ENCRYPT, SYNTHESIZE, MASK, PASS, BLOCK

### C4d — Threat Detection

```mermaid
graph TB
    subgraph "5 Threat Models"
        T1["PROMPT_INJECTION<br/>10 regex patterns"]
        T2["UNCONTROLLED_RAG<br/>7 broad-query patterns"]
        T3["PRIVILEGE_ESCALATION<br/>5 escalation patterns"]
        T4["SALAMI_SLICING<br/>PII density + named subjects"]
        T5["OVERBROAD_API<br/>5 overbroad patterns"]
    end

    INPUT["Payload + Context + Agent Role"] --> ANALYZE["_analyze_threat()"]
    ANALYZE --> T1
    ANALYZE --> T2
    ANALYZE --> T3
    ANALYZE --> T4
    ANALYZE --> T5
    T1 --> RESULT["(detected, signals[], severity, risk_score, action)"]
    T2 --> RESULT
    T3 --> RESULT
    T4 --> RESULT
    T5 --> RESULT
```

### C4e — Audit Hash Chain

```mermaid
graph LR
    E1["Event 1<br/>hash: sha256(id+type+ts)<br/>prev_hash: 000...0"] --> E2["Event 2<br/>hash: sha256(id+type+ts)<br/>prev_hash: E1.hash"]
    E2 --> E3["Event 3<br/>hash: sha256(id+type+ts)<br/>prev_hash: E2.hash"]
    E3 --> EN["Event N<br/>...<br/>prev_hash: E(N-1).hash"]
```

The `/api/audit/verify` endpoint walks the entire chain and reports any broken links where `event[i].prev_hash != event[i-1].hash`.

### C4f — Interception Surfaces

```mermaid
graph TB
    subgraph "4 Interception Surfaces"
        MCP["MCP<br/>Model Context Protocol<br/>JSON-RPC 2.0, SSE"]
        A2A["A2A<br/>Agent-to-Agent<br/>HTTP/2, gRPC, Task envelope"]
        LLM_API["LLM_API<br/>API Gateway<br/>OpenAI, Anthropic, SSE"]
        RAG["RAG<br/>Retrieval Pipeline<br/>Vector DB, LangChain"]
    end

    PAYLOAD["Inbound Payload"] --> DETECT["Detection Engine"]
    DETECT --> RISK["Risk Scoring<br/>(severity weights)"]
    RISK --> ACTION{Risk >= 60?}
    ACTION -->|Yes| BLOCKED["BLOCKED"]
    ACTION -->|No, entities > 0| TOKENIZED["TOKENIZED"]
    ACTION -->|No entities| PASSED["PASSED"]
```

**Risk Scoring Weights:**

| Entity Type | Weight |
|-------------|--------|
| API_KEY | 30 |
| SSN, CREDIT_CARD | 25 |
| IBAN, PASSPORT | 20 |
| DRIVERS_LICENSE | 18 |
| EMAIL, PHONE | 8 |
| PERSON_NAME | 6 |
| IP_ADDRESS | 5 |
| DATE | 3 |

---

## Database Schema

```mermaid
erDiagram
    scan_sessions {
        int id PK
        text name
        text created_at
        text expires_at
        text status
        text agent_id
        text policy_id
        int entities_protected
        int tokens_generated
    }

    entities_detected {
        int id PK
        int session_id FK
        text entity_type
        text original_text
        text token
        real confidence
        text action
        text detected_at
    }

    policies {
        int id PK
        text policy_id UK
        text name
        text yaml_content
        text status
        text compliance_packs
        text created_at
        text updated_at
    }

    audit_events {
        int id PK
        text event_id UK
        text event_type
        int session_id
        text agent_id
        text policy_id
        text entities_json
        real latency_ms
        text hash
        text prev_hash
    }

    interceptor_logs {
        int id PK
        text surface
        text direction
        text agent_id
        int entities_found
        text action_taken
        real latency_ms
    }

    compliance_frameworks {
        int id PK
        text code UK
        text name
        text category
        int controls_total
        int controls_passing
        text status
    }

    compliance_controls {
        int id PK
        text framework_code FK
        text control_id
        text name
        text status
        text evidence_type
        text severity
    }

    threat_events {
        int id PK
        text threat_type
        text severity
        text agent_id
        text description
        text status
    }

    settings {
        int id PK
        int vault_ttl
        int session_timeout
        real confidence_threshold
        text enabled_entity_types
    }

    agent_roles {
        int id PK
        text role_name UK
        text permissions
        int is_default
    }

    scan_sessions ||--o{ entities_detected : "has many"
    scan_sessions ||--o{ audit_events : "logged by"
    compliance_frameworks ||--o{ compliance_controls : "has many"
```
