"""DataShield AI — Agentic Data Privacy Infrastructure."""
# AI keys are NEVER stored server-side. Keys are passed via X-API-Key header per request.
from __future__ import annotations
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from datashield.database import init_db
from datashield.routers import scanner, sessions, policies, audit, interceptor, compliance, threats, dashboard, settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="DataShield AI",
    description="Agentic Data Privacy Infrastructure — PII detection, tokenization, policy enforcement, audit trail, threat detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scanner.router)
app.include_router(sessions.router)
app.include_router(policies.router)
app.include_router(audit.router)
app.include_router(interceptor.router)
app.include_router(compliance.router)
app.include_router(threats.router)
app.include_router(dashboard.router)
app.include_router(settings.router)


@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "datashield-ai", "version": "1.0.0"}


# --- Static file serving for Docker production builds ---
_static_dir = Path(__file__).resolve().parent.parent.parent.parent / "static"
if not _static_dir.is_dir():
    _static_dir = Path("/app/static")  # Docker fallback
if _static_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_static_dir / "assets")), name="static")

    @app.get("/{path:path}")
    async def spa_fallback(path: str):
        """Serve index.html for all non-API routes (SPA catch-all)."""
        return FileResponse(str(_static_dir / "index.html"))
