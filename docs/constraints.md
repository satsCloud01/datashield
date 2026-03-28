# DataShield AI — Constraints & Architecture Decisions

> Version 1.0 · Last updated 2026-03-27

---

## Table of Contents

1. [Architecture Decision Records](#architecture-decision-records)
2. [Non-Functional Constraints](#non-functional-constraints)
3. [Technology Choices & Rationale](#technology-choices--rationale)

---

## Architecture Decision Records

### ADR-001: SQLite for Persistence

**Status:** Accepted

**Context:** The system needs structured storage for sessions, entities, policies, audit events, compliance data, and threats. Options considered: PostgreSQL, MySQL, SQLite, DynamoDB.

**Decision:** Use SQLite via aiosqlite for all persistence.

**Rationale:**
- Zero external dependency — no database server to install, configure, or maintain
- Single-file database (`datashield.db`) simplifies deployment and backup
- Sufficient for demo/POC workloads (single-writer, moderate read concurrency)
- aiosqlite provides async compatibility with FastAPI's event loop
- Migration to PostgreSQL is straightforward if production scale demands it

**Consequences:**
- No concurrent write scaling
- No built-in replication or HA
- Database file must be on local filesystem

---

### ADR-002: In-Memory Token Vault

**Status:** Accepted

**Context:** The token vault maps original text to obfuscated replacements and must support fast lookups for real-time interception. Options considered: Redis, Memcached, in-memory Python dict, encrypted file store.

**Decision:** Use in-memory Python data structures (dict + dataclasses) for the vault.

**Rationale:**
- Sub-millisecond lookup latency
- No external dependency (Redis/Memcached not required)
- Session-scoped by design — vault data is ephemeral and should not persist beyond the session
- Simplifies security: no sensitive data written to disk or external cache
- Vault references are generated per session and invalidated on expiry/purge

**Consequences:**
- Vault data is lost on server restart
- Memory-bound — large sessions with many tokens consume server RAM
- Not suitable for multi-instance deployments without shared state

---

### ADR-003: Regex-Based Detection Engine

**Status:** Accepted

**Context:** The detection engine must identify 57+ entity types across 6 categories (PII, PHI, PCI, FINANCIAL, IP_CODE, CUSTOM). Options considered: spaCy NER, Presidio, custom regex, transformer-based NER.

**Decision:** Use a custom 4-stage regex pipeline with context-aware confidence scoring.

**Rationale:**
- Zero ML model dependency — no model downloads, GPU requirements, or inference latency
- Deterministic and auditable — every detection traces to a specific regex pattern
- Sub-5ms processing for typical payloads (1000 tokens)
- 4-stage pipeline (Regex, Context, Validation, Dedup) provides layered accuracy
- Luhn validation for credit cards, checksum validation for structured IDs
- Easy to extend: add a regex pattern and metadata to the registry

**Consequences:**
- Lower recall than ML-based NER for unstructured names and addresses
- Requires manual pattern maintenance as new entity formats emerge
- Context scoring is heuristic, not learned

---

### ADR-004: BYOK Pattern (No Server-Side Key Storage)

**Status:** Accepted

**Context:** DataShield does not call LLM APIs directly (it intercepts data flowing to them), but the principle of zero credential storage is enforced system-wide.

**Decision:** No API keys, credentials, or secrets are stored server-side. Any future AI features would use the BYOK (Bring Your Own Key) pattern with keys in browser localStorage, passed via headers.

**Rationale:**
- Eliminates credential exfiltration risk from the server
- Aligns with the security posture of a privacy infrastructure product
- Consistent with the pattern used across the SatsZone portfolio

**Consequences:**
- Users must provide keys per browser session
- No server-side API calls to LLM providers in current architecture

---

### ADR-005: Session-Scoped Tokenization

**Status:** Accepted

**Context:** Tokenized data needs a lifecycle — it cannot persist indefinitely as that creates a new attack surface. Options: global vault, session-scoped, time-based, request-scoped.

**Decision:** All tokenization is session-scoped with configurable TTL (default: 1800 seconds). Sessions can be extended (up to 168 hours) or purged on demand.

**Rationale:**
- Ephemeral by default — reduces the window of exposure
- Session purge permanently destroys all token mappings (supports GDPR right to erasure)
- TTL ensures stale sessions are automatically invalidated
- Configurable via Settings page for different use cases

**Consequences:**
- Users must restore within the TTL window or lose access to original text
- No persistent cross-session token mapping

---

### ADR-006: Policy-as-Code (YAML)

**Status:** Accepted

**Context:** Compliance policies must be declarative, version-controllable, and auditable. Options: GUI-only, JSON, YAML, Rego (OPA), custom DSL.

**Decision:** Use YAML for policy definition with server-side validation.

**Rationale:**
- Human-readable and editable
- GitOps-compatible — policies can be version-controlled alongside infrastructure code
- Standard format with broad tooling support
- Validation on write prevents invalid policies from being stored
- Compliance packs link policies to regulatory frameworks

**Consequences:**
- No complex logic (conditions, functions) — rules are entity_type-to-action mappings
- Policy evaluation is simple pattern matching, not a full rule engine

---

## Non-Functional Constraints

### Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Detection latency | < 5ms P99 per 1000 tokens | Regex-based, no ML inference |
| Tokenization latency | < 2ms per entity | In-memory dict lookup |
| Interception simulation | < 10ms end-to-end | Detection + scoring + action |
| API response time | < 50ms P95 | Simple CRUD with SQLite |
| Audit chain verification | < 100ms for 1000 events | Sequential hash comparison |

### Capacity

| Resource | Limit | Notes |
|----------|-------|-------|
| Token vault | In-memory, session-scoped | Bounded by server RAM |
| SQLite database | Single-writer, ~1000 req/s read | Sufficient for demo workloads |
| Batch interception | Max 100 payloads per request | Server-enforced limit |
| Session TTL | 1800s default, max 168 hours | Configurable via Settings |
| Entity types | 57 built-in | Extensible via detection engine registry |

### Compliance

| Framework | Controls | Automated Assessment |
|-----------|----------|---------------------|
| GDPR | Entity detection, vault ops, erasure, audit trail, policy config | Yes |
| HIPAA | PHI detection, access control, audit trail | Yes |
| PCI-DSS-4 | Card/IBAN detection, vault operations | Yes |
| CCPA | PII detection, consent tracking, erasure | Yes |
| SOX | Financial controls, audit trail | Yes |
| EU-AI-ACT | AI transparency, data protection | Yes |
| ISO-27701 | Privacy management, entity coverage | Yes |
| FERPA | Educational records, PII protection | Yes |

### Security

| Control | Implementation |
|---------|---------------|
| Audit trail integrity | SHA-256 hash chain with prev_hash linking |
| Data at rest | SQLite file (entities are tokenized before storage in active flows) |
| CORS | Permissive in dev (`*`), restricted in production |
| Input validation | Pydantic v2 models on all request bodies |
| Session isolation | Each session has independent vault mappings |
| Vault purge | Irreversible deletion of entity mappings + audit event logged |

---

## Technology Choices & Rationale

| Technology | Role | Why |
|-----------|------|-----|
| **FastAPI** | API framework | Async-native, auto-generated OpenAPI docs, Pydantic integration, high performance |
| **Python 3.12** | Runtime | Latest stable, pattern matching, performance improvements |
| **React 18** | Frontend framework | Component-based, large ecosystem, team familiarity |
| **Vite** | Build tool | Fast HMR, native ESM, minimal config |
| **Tailwind CSS** | Styling | Utility-first, consistent design system, rapid prototyping |
| **aiosqlite** | Database driver | Async SQLite access compatible with FastAPI's event loop |
| **Pydantic v2** | Validation | Type-safe request/response models, serialization, auto-docs |
| **PyYAML** | Policy parsing | Standard YAML library, safe_load for security |
| **SHA-256** | Audit hashing | Industry-standard, collision-resistant, fast computation |
| **dataclasses** | Domain models | Lightweight, no ORM overhead, clear structure |

### What Was Explicitly Avoided

| Technology | Reason |
|-----------|--------|
| SQLAlchemy ORM | Unnecessary complexity for a demo; raw SQL with aiosqlite is simpler |
| Redis/Memcached | External dependency not justified for session-scoped in-memory vault |
| spaCy/Presidio | ML model dependency adds install complexity and inference latency |
| TypeScript | Frontend is plain JSX for consistency with portfolio conventions |
| Docker Compose (for DB) | SQLite eliminates the need for a separate database container |
