# DataShield AI

**Agentic Data Privacy Infrastructure**

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![React 18](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green)

DataShield AI is an agentic data privacy platform that automates PII detection, tokenization, policy enforcement, compliance monitoring, and threat detection across enterprise data pipelines. It combines intelligent scanning agents with real-time interception to provide end-to-end privacy infrastructure without manual configuration.

> **Screenshot placeholder** -- add a screenshot of the dashboard here.

---

## Features

- **PII Scanner Agent** -- Automated detection and classification of personally identifiable information across structured and unstructured data sources
- **Tokenization & Masking** -- Reversible tokenization and format-preserving masking with configurable strategies per data type
- **Policy Engine** -- Declarative privacy policies with rule-based enforcement, inheritance, and conflict resolution
- **Compliance Dashboard** -- Real-time compliance posture against GDPR, CCPA, HIPAA, and PCI-DSS with gap analysis
- **Threat Detection** -- Anomaly-based detection of data exfiltration, unauthorized access patterns, and policy violations
- **Audit Trail** -- Immutable, queryable audit log of every data access, transformation, and policy decision

---

## Quick Start

### Local Development

```bash
# Clone and enter
git clone https://github.com/satsCloud01/datashield.git
cd datashield

# Start both servers
./start.sh
```

Backend runs on `http://localhost:8007`, frontend on `http://localhost:5179`.

### Docker Deployment

```bash
# Build and run
docker compose up -d

# Access at http://localhost:8027
```

To deploy on a remote server behind a reverse proxy, map port 8027 to your domain.

---

## Architecture

The system follows a layered architecture with agentic processing pipelines:

```
Frontend (React 18 + Tailwind + Recharts)
    |
FastAPI Gateway (REST + WebSocket)
    |
+-- Scanner Agent     -- PII detection pipeline
+-- Interceptor Agent -- Real-time data interception
+-- Policy Engine     -- Rule evaluation & enforcement
+-- Threat Detector   -- Anomaly scoring & alerting
+-- Compliance Agent  -- Regulation mapping & gap analysis
    |
SQLite (audit logs, policies, sessions)
```

See [docs/architecture.md](docs/architecture.md) for C1-C4 diagrams.

---

## API Reference

All endpoints are prefixed with `/api`. Interactive docs available at `/docs` when running locally.

| Module | Prefix | Description |
|---|---|---|
| Scanner | `/api/scanner` | PII detection and classification |
| Sessions | `/api/sessions` | Scan session management |
| Policies | `/api/policies` | Privacy policy CRUD and evaluation |
| Audit | `/api/audit` | Audit trail queries and export |
| Interceptor | `/api/interceptor` | Real-time data interception rules |
| Compliance | `/api/compliance` | Regulation compliance checks |
| Threats | `/api/threats` | Threat detection and alerts |
| Dashboard | `/api/dashboard` | Aggregated metrics and stats |
| Settings | `/api/settings` | Configuration management |

See [docs/api-spec.md](docs/api-spec.md) for full specification.

---

## Testing

```bash
# Backend tests (423 tests)
cd backend && PYTHONPATH=src .venv/bin/pytest tests/ -v

# Frontend E2E tests (100 tests)
cd frontend && npx playwright test
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Tailwind CSS 4, Recharts, React Router 6 |
| Backend | FastAPI, Python 3.12, Pydantic, HTTPX |
| Database | SQLite (aiosqlite) |
| AI | Claude API (BYOK via UI) |
| Testing | pytest + pytest-asyncio, Playwright |
| Deployment | Docker, docker-compose |

---

## License

MIT
