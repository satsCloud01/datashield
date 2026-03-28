"""Shared fixtures for DataShield AI tests."""
from __future__ import annotations

import os
import tempfile

# Point DB to a temp file BEFORE importing anything from datashield
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()

import datashield.database as _db_mod
from pathlib import Path
_db_mod.DB_PATH = Path(_tmp.name)

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from datashield.main import app
from datashield.database import init_db
from datashield.services.detection_engine import detect


_db_initialized = False


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """Async HTTP client wired to the FastAPI app."""
    global _db_initialized
    if not _db_initialized:
        await init_db()
        _db_initialized = True
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def detection_engine():
    """Return the detect function for direct unit testing."""
    return detect
