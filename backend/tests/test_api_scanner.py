"""Tests for scanner API endpoints — 42 tests."""
from __future__ import annotations

import pytest
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


class TestScanEndpoint:
    """POST /api/scan — 12 tests."""

    async def test_scan_ssn(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "SSN: 123-45-6789"})
        assert resp.status_code == 200
        data = resp.json()
        types = {e["entity_type"] for e in data["entities"]}
        assert "SSN" in types

    async def test_scan_email(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "email john@example.com"})
        assert resp.status_code == 200
        types = {e["entity_type"] for e in data} if False else {e["entity_type"] for e in resp.json()["entities"]}
        assert "EMAIL" in types

    async def test_scan_credit_card(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "Card: 4111-1111-1111-1111"})
        assert resp.status_code == 200
        data = resp.json()
        types = {e["entity_type"] for e in data["entities"]}
        assert "CREDIT_CARD_PAN" in types
        cc_entity = next(e for e in data["entities"] if e["entity_type"] == "CREDIT_CARD_PAN")
        assert cc_entity["category"] == "PCI"

    async def test_scan_multiple_pii(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={
            "text": "SSN 123-45-6789, email john@example.com, phone (212) 555-0147"
        })
        data = resp.json()
        assert data["count"] >= 3
        types = {e["entity_type"] for e in data["entities"]}
        assert "SSN" in types
        assert "EMAIL" in types

    async def test_scan_no_pii(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "The weather is nice today."})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["entities"] == []

    async def test_scan_returns_entity_metadata(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "SSN 456-78-9012"})
        data = resp.json()
        entity = data["entities"][0]
        for field in ("category", "regulatory_basis", "risk_level", "default_action"):
            assert field in entity, f"Missing field: {field}"
        assert entity["category"] == "PII"
        assert entity["risk_level"] == "CRITICAL"

    async def test_scan_with_session_name(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "SSN 123-45-6789", "session_name": "named-scan"})
        assert resp.status_code == 200
        assert "session_id" in resp.json()

    async def test_scan_with_agent_id(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "SSN 123-45-6789", "agent_id": "kyc-agent"})
        assert resp.status_code == 200
        sid = resp.json()["session_id"]
        # Verify session stored agent_id
        sess = await client.get(f"/api/sessions/{sid}")
        assert sess.json()["agent_id"] == "kyc-agent"

    async def test_scan_response_has_session_id(self, client: AsyncClient):
        resp = await client.post("/api/scan", json={"text": "SSN 123-45-6789"})
        assert "session_id" in resp.json()
        assert isinstance(resp.json()["session_id"], int)

    async def test_scan_long_text(self, client: AsyncClient):
        long_text = "No PII here. " * 200 + " SSN 123-45-6789 " + " More text. " * 100
        resp = await client.post("/api/scan", json={"text": long_text})
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_scan_html_embedded_pii(self, client: AsyncClient):
        html = '<div class="user"><span>SSN: 123-45-6789</span><a href="mailto:test@example.com">email</a></div>'
        resp = await client.post("/api/scan", json={"text": html})
        data = resp.json()
        types = {e["entity_type"] for e in data["entities"]}
        assert "SSN" in types
        assert "EMAIL" in types

    async def test_scan_json_payload_with_pii(self, client: AsyncClient):
        json_text = '{"customer": {"ssn": "123-45-6789", "email": "john@example.com"}}'
        resp = await client.post("/api/scan", json={"text": json_text})
        data = resp.json()
        assert data["count"] >= 2


class TestProtectEndpoint:
    """POST /api/protect — 12 tests."""

    async def test_protect_tokenize(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789", "mode": "TOKENIZE"})
        assert resp.status_code == 200
        data = resp.json()
        assert "123-45-6789" not in data["sanitized_text"]
        assert "<<" in data["sanitized_text"] or "SSN" in data["sanitized_text"]

    async def test_protect_redact(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789", "mode": "REDACT"})
        assert resp.status_code == 200
        data = resp.json()
        assert "[REDACTED]" in data["sanitized_text"]
        assert "123-45-6789" not in data["sanitized_text"]

    async def test_protect_pseudonymize(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789", "mode": "PSEUDONYMIZE"})
        assert resp.status_code == 200
        assert "123-45-6789" not in resp.json()["sanitized_text"]

    async def test_protect_generalize(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "email john@example.com", "mode": "GENERALIZE"})
        assert resp.status_code == 200
        assert "john@example.com" not in resp.json()["sanitized_text"]

    async def test_protect_encrypt(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789", "mode": "ENCRYPT"})
        assert resp.status_code == 200
        data = resp.json()
        assert "ENC:" in data["sanitized_text"]
        assert "123-45-6789" not in data["sanitized_text"]

    async def test_protect_default_mode_is_tokenize(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "TOKENIZE"

    async def test_protect_returns_vault_ref(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789"})
        data = resp.json()
        assert "vault_ref" in data
        assert data["vault_ref"] is not None
        assert len(data["vault_ref"]) > 0

    async def test_protect_returns_entities_protected_count(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789 email john@example.com"})
        data = resp.json()
        assert data["entities_protected"] >= 2

    async def test_protect_returns_latency_ms(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789"})
        data = resp.json()
        assert "latency_ms" in data
        assert isinstance(data["latency_ms"], (int, float))
        assert data["latency_ms"] >= 0

    async def test_protect_no_pii_text(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "Hello world, no PII here."})
        assert resp.status_code == 200
        data = resp.json()
        assert data["vault_ref"] is not None
        assert data["entities_protected"] == 0

    async def test_protect_many_entities(self, client: AsyncClient):
        text = (
            "SSN 123-45-6789, SSN 987-65-4321, email a@b.com, email c@d.com, "
            "phone (212) 555-0147, phone (646) 555-0312, card 4111-1111-1111-1111, "
            "IP 192.168.1.1, IBAN DE89370400440532013000, key sk-proj-abc123def456ghi789"
        )
        resp = await client.post("/api/protect", json={"text": text, "mode": "TOKENIZE"})
        data = resp.json()
        assert data["entities_protected"] >= 5

    async def test_protect_creates_db_session(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789", "session_name": "db-check"})
        sid = resp.json()["session_id"]
        sess = await client.get(f"/api/sessions/{sid}")
        assert sess.status_code == 200
        assert sess.json()["status"] == "ACTIVE"


class TestRestoreEndpoint:
    """POST /api/restore — 6 tests."""

    async def test_restore_valid_ref(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789", "mode": "TOKENIZE"})
        vault_ref = resp.json()["vault_ref"]
        resp2 = await client.post("/api/restore", json={"vault_ref": vault_ref})
        assert resp2.status_code == 200
        assert "original_text" in resp2.json()

    async def test_restore_returns_entities_restored(self, client: AsyncClient):
        resp = await client.post("/api/protect", json={"text": "SSN 123-45-6789 email john@example.com", "mode": "TOKENIZE"})
        vault_ref = resp.json()["vault_ref"]
        resp2 = await client.post("/api/restore", json={"vault_ref": vault_ref})
        assert resp2.json()["entities_restored"] >= 2

    async def test_restore_invalid_ref_404(self, client: AsyncClient):
        resp = await client.post("/api/restore", json={"vault_ref": "invalid_ref_12345"})
        assert resp.status_code == 404

    async def test_restore_empty_ref_404(self, client: AsyncClient):
        resp = await client.post("/api/restore", json={"vault_ref": ""})
        assert resp.status_code == 404

    async def test_round_trip_matches_original(self, client: AsyncClient):
        original = "SSN 123-45-6789"
        resp = await client.post("/api/protect", json={"text": original, "mode": "TOKENIZE"})
        vault_ref = resp.json()["vault_ref"]
        resp2 = await client.post("/api/restore", json={"vault_ref": vault_ref})
        assert resp2.json()["original_text"] == original

    async def test_round_trip_multi_entity(self, client: AsyncClient):
        original = "SSN 123-45-6789, email john@example.com, phone (212) 555-0147"
        resp = await client.post("/api/protect", json={"text": original, "mode": "TOKENIZE"})
        vault_ref = resp.json()["vault_ref"]
        resp2 = await client.post("/api/restore", json={"vault_ref": vault_ref})
        assert resp2.json()["original_text"] == original


class TestBatchScan:
    """POST /api/scan/batch — 4 tests."""

    async def test_batch_three_texts(self, client: AsyncClient):
        resp = await client.post("/api/scan/batch", json={
            "texts": ["SSN 123-45-6789", "email john@example.com", "The weather is nice."]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 3

    async def test_batch_returns_totals(self, client: AsyncClient):
        resp = await client.post("/api/scan/batch", json={
            "texts": ["SSN 123-45-6789", "email john@example.com"]
        })
        data = resp.json()
        assert data["total_texts"] == 2
        assert data["total_entities"] >= 2

    async def test_batch_mix_pii_and_clean(self, client: AsyncClient):
        resp = await client.post("/api/scan/batch", json={
            "texts": ["SSN 123-45-6789", "Clean text", "email a@b.com", "Also clean"]
        })
        data = resp.json()
        assert data["results"][0]["count"] >= 1
        assert data["results"][1]["count"] == 0
        assert data["results"][2]["count"] >= 1
        assert data["results"][3]["count"] == 0

    async def test_batch_empty_texts(self, client: AsyncClient):
        resp = await client.post("/api/scan/batch", json={"texts": []})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_texts"] == 0
        assert data["total_entities"] == 0
        assert data["results"] == []


class TestEntityRegistry:
    """GET /api/scan/entity-registry — 3 tests."""

    async def test_registry_returns_dict(self, client: AsyncClient):
        resp = await client.get("/api/scan/entity-registry")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert len(data) >= 50

    async def test_registry_has_all_categories(self, client: AsyncClient):
        resp = await client.get("/api/scan/entity-registry")
        data = resp.json()
        categories = set()
        for key, meta in data.items():
            if isinstance(meta, dict) and "category" in meta:
                categories.add(meta["category"])
        assert len(categories) >= 4  # PII, PHI, PCI, FINANCIAL at minimum

    async def test_registry_entity_has_required_fields(self, client: AsyncClient):
        resp = await client.get("/api/scan/entity-registry")
        data = resp.json()
        for key, meta in data.items():
            if isinstance(meta, dict):
                for field in ("category", "regulatory_basis", "default_action", "risk_level"):
                    assert field in meta, f"Entity {key} missing {field}"
                break  # Just check at least one


class TestSamples:
    """GET /api/scan/samples — 2 tests."""

    async def test_samples_returns_five(self, client: AsyncClient):
        resp = await client.get("/api/scan/samples")
        assert resp.status_code == 200
        assert len(resp.json()) == 5

    async def test_samples_have_required_fields(self, client: AsyncClient):
        resp = await client.get("/api/scan/samples")
        for sample in resp.json():
            assert "name" in sample
            assert "description" in sample
            assert "text" in sample
            assert len(sample["text"]) > 20


class TestValidate:
    """POST /api/scan/validate — 3 tests."""

    async def test_validate_clean_text(self, client: AsyncClient):
        resp = await client.post("/api/scan/validate", json={"text": "No PII here at all."})
        assert resp.status_code == 200
        data = resp.json()
        assert data["clean"] is True
        assert data["entities_found"] == 0

    async def test_validate_text_with_pii(self, client: AsyncClient):
        resp = await client.post("/api/scan/validate", json={"text": "SSN 123-45-6789"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["clean"] is False
        assert data["entities_found"] >= 1
        assert "remaining_entities" in data

    async def test_validate_tokenized_text_is_clean(self, client: AsyncClient):
        resp = await client.post("/api/scan/validate", json={"text": "User data: <<SSN_X1>> and <<EMAIL_X2>>"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["clean"] is True
