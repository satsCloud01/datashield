# DataShield AI — Documentation

> Agentic Data Privacy Infrastructure — PII detection, tokenization, policy enforcement, audit trail, threat detection

---

## Quick Reference

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | C1-C4 architecture diagrams (system context, containers, components, code level), database schema, detection pipeline, vault lifecycle, threat models |
| [domain-model.md](domain-model.md) | Entity relationship diagram, aggregate roots, value objects, domain glossary |
| [api-spec.md](api-spec.md) | Complete API specification for all 55 endpoints across 10 routers with request/response examples |
| [constraints.md](constraints.md) | 6 architecture decision records (ADRs), non-functional constraints, technology choices and rationale |

---

## System Overview

**DataShield AI** sits between AI agents and LLM APIs, intercepting data flows to protect sensitive information.

**Core Capabilities:**
- **Detection Engine** — 4-stage regex pipeline detecting 57 entity types across 6 categories (PII, PHI, PCI, FINANCIAL, IP_CODE, CUSTOM)
- **Token Vault** — Session-scoped reversible tokenization with 6 obfuscation modes (REDACT, TOKENIZE, PSEUDONYMIZE, GENERALIZE, ENCRYPT, SYNTHESIZE)
- **Policy Engine** — YAML-based policy-as-code with compliance pack mapping
- **Interception** — 4 surfaces (MCP, A2A, LLM_API, RAG) with risk scoring and automatic blocking
- **Threat Detection** — 5 agentic threat models (Prompt Injection, Uncontrolled RAG, Privilege Escalation, Salami Slicing, Overbroad API)
- **Compliance** — 8 frameworks (GDPR, HIPAA, PCI-DSS-4, CCPA, SOX, EU-AI-ACT, ISO-27701, FERPA) with automated assessment
- **Audit Trail** — SHA-256 hash-chained tamper-evident event log

**Stack:** FastAPI (Python 3.12) + React 18 + Vite + Tailwind CSS + SQLite

**Ports:** Backend 8007, Frontend 5179
