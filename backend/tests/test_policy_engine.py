"""Exhaustive tests for the policy engine — 43 tests covering evaluation, exceptions, conflicts, validation, compliance, diff, simulation."""
from __future__ import annotations

import pytest
from datashield.services.policy_engine import (
    evaluate, detect_conflicts, validate_policy, validate_yaml,
    diff_policies, get_compliance_pack, list_compliance_packs,
    get_compliance_mapping, simulate, COMPLIANCE_PACKS,
)


# ── Policy fixtures ──────────────────────────────────────────────────

SIMPLE_POLICY = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: PSEUDONYMIZE
  - entity_type: PHONE
    action: TOKENIZE
"""

ROLE_POLICY = """
rules:
  - entity_type: SSN
    action: REDACT
    roles: [analyst, viewer]
  - entity_type: SSN
    action: PASS
    roles: [admin]
  - entity_type: EMAIL
    action: TOKENIZE
"""

EXCEPTION_POLICY = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
  - entity_type: PHONE
    action: TOKENIZE
exceptions:
  - agent_id: agent-audit-08
    entity_types: [SSN, EMAIL]
    action: PASS
"""

MULTI_EXCEPTION_POLICY = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
exceptions:
  - agent_id: agent-audit-08
    entity_types: [SSN, EMAIL]
    action: PASS
  - agent_id: agent-compliance-01
    entity_types: [SSN]
    action: PASS
"""

CLASSIFICATION_POLICY = """
rules:
  - entity_type: SSN
    action: REDACT
    classification: CONFIDENTIAL
  - entity_type: IP_ADDRESS
    action: MASK
    classification: RESTRICTED
"""


# ═══════════════════════════════════════════════════════════════════════
# EVALUATE (10 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestEvaluate:
    def test_tokenize_action(self):
        decisions = evaluate(SIMPLE_POLICY, ["PHONE"])
        assert decisions[0].action == "TOKENIZE"

    def test_redact_action(self):
        decisions = evaluate(SIMPLE_POLICY, ["SSN"])
        assert decisions[0].action == "REDACT"

    def test_multiple_entity_types_correct_per_type(self):
        decisions = evaluate(SIMPLE_POLICY, ["SSN", "EMAIL", "PHONE"])
        by_type = {d.entity_type: d for d in decisions}
        assert by_type["SSN"].action == "REDACT"
        assert by_type["EMAIL"].action == "PSEUDONYMIZE"
        assert by_type["PHONE"].action == "TOKENIZE"

    def test_agent_id_with_role_matching(self):
        decisions = evaluate(ROLE_POLICY, ["SSN"], agent_role="admin")
        assert decisions[0].action == "PASS"

    def test_agent_id_not_in_policy_default_deny(self):
        decisions = evaluate(SIMPLE_POLICY, ["UNKNOWN_TYPE"])
        assert decisions[0].action == "REDACT"
        assert "unknown" in decisions[0].reason.lower() or "default" in decisions[0].reason.lower()

    def test_agent_role_analyst(self):
        decisions = evaluate(ROLE_POLICY, ["SSN"], agent_role="analyst")
        assert decisions[0].action == "REDACT"

    def test_no_policy_uses_defaults(self):
        decisions = evaluate(None, ["SSN", "EMAIL", "DATE"])
        by_type = {d.entity_type: d for d in decisions}
        assert by_type["SSN"].action == "REDACT"
        assert by_type["EMAIL"].action == "TOKENIZE"
        assert by_type["DATE"].action == "PASS"

    def test_empty_entity_list(self):
        decisions = evaluate(SIMPLE_POLICY, [])
        assert decisions == []

    def test_confidential_and_restricted_levels(self):
        decisions = evaluate(CLASSIFICATION_POLICY, ["SSN", "IP_ADDRESS"])
        by_type = {d.entity_type: d for d in decisions}
        assert by_type["SSN"].action == "REDACT"
        assert by_type["IP_ADDRESS"].action == "MASK"

    def test_evaluate_returns_compliance_refs(self):
        policy_with_packs = """
rules:
  - entity_type: SSN
    action: REDACT
compliance_packs:
  - GDPR
  - HIPAA
"""
        decisions = evaluate(policy_with_packs, ["SSN"])
        assert decisions[0].action == "REDACT"
        assert len(decisions[0].compliance_refs) >= 1


# ═══════════════════════════════════════════════════════════════════════
# AGENT EXCEPTIONS (6 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestAgentExceptions:
    def test_agent_in_exceptions_gets_pass(self):
        decisions = evaluate(EXCEPTION_POLICY, ["SSN"], agent_id="agent-audit-08")
        assert decisions[0].action == "PASS"

    def test_agent_not_in_exceptions_gets_policy_action(self):
        decisions = evaluate(EXCEPTION_POLICY, ["SSN"], agent_id="agent-other")
        assert decisions[0].action == "REDACT"

    def test_exception_for_specific_entity_types_only(self):
        decisions = evaluate(EXCEPTION_POLICY, ["SSN", "EMAIL", "PHONE"], agent_id="agent-audit-08")
        by_type = {d.entity_type: d for d in decisions}
        assert by_type["SSN"].action == "PASS"
        assert by_type["EMAIL"].action == "PASS"
        assert by_type["PHONE"].action == "TOKENIZE"  # not in exception list

    def test_multiple_agents_in_exceptions(self):
        d1 = evaluate(MULTI_EXCEPTION_POLICY, ["SSN"], agent_id="agent-audit-08")
        d2 = evaluate(MULTI_EXCEPTION_POLICY, ["SSN"], agent_id="agent-compliance-01")
        assert d1[0].action == "PASS"
        assert d2[0].action == "PASS"

    def test_exception_combined_with_role(self):
        policy = """
rules:
  - entity_type: SSN
    action: REDACT
    roles: [analyst]
exceptions:
  - agent_role: admin
    entity_types: [SSN]
    action: PASS
"""
        decisions = evaluate(policy, ["SSN"], agent_role="admin")
        assert decisions[0].action == "PASS"

    def test_exception_overrides_confidential(self):
        policy = """
rules:
  - entity_type: SSN
    action: REDACT
    classification: CONFIDENTIAL
exceptions:
  - agent_id: trusted-agent
    entity_types: [SSN]
    action: PASS
"""
        decisions = evaluate(policy, ["SSN"], agent_id="trusted-agent")
        assert decisions[0].action == "PASS"
        assert decisions[0].overridden_by is not None


# ═══════════════════════════════════════════════════════════════════════
# CONFLICT DETECTION (6 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestConflictDetection:
    def test_conflicting_actions_detected(self):
        policy = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: SSN
    action: PASS
"""
        conflicts = detect_conflicts(policy)
        assert len(conflicts) >= 1
        assert conflicts[0].entity_type == "SSN"

    def test_no_conflicts_clean_policy(self):
        conflicts = detect_conflicts(SIMPLE_POLICY)
        assert len(conflicts) == 0

    def test_conflict_message_describes_entities(self):
        policy = """
rules:
  - entity_type: EMAIL
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
"""
        conflicts = detect_conflicts(policy)
        assert len(conflicts) >= 1
        assert "EMAIL" in conflicts[0].description

    def test_overlapping_rules_different_actions(self):
        policy = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: SSN
    action: TOKENIZE
  - entity_type: SSN
    action: PASS
"""
        conflicts = detect_conflicts(policy)
        assert len(conflicts) >= 2  # 3 rules → at least 2 conflict pairs

    def test_tokenize_vs_redact_conflict(self):
        policy = """
rules:
  - entity_type: PHONE
    action: TOKENIZE
  - entity_type: PHONE
    action: REDACT
"""
        conflicts = detect_conflicts(policy)
        assert len(conflicts) == 1
        assert "TOKENIZE" in conflicts[0].description
        assert "REDACT" in conflicts[0].description

    def test_multiple_conflicts_in_one_policy(self):
        policy = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: SSN
    action: PASS
  - entity_type: EMAIL
    action: TOKENIZE
  - entity_type: EMAIL
    action: PSEUDONYMIZE
"""
        conflicts = detect_conflicts(policy)
        types = {c.entity_type for c in conflicts}
        assert "SSN" in types
        assert "EMAIL" in types


# ═══════════════════════════════════════════════════════════════════════
# VALIDATION (8 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestValidation:
    def test_valid_policy_passes(self):
        result = validate_policy(SIMPLE_POLICY)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_invalid_yaml_syntax(self):
        result = validate_policy("{{bad yaml: [")
        assert result["valid"] is False
        assert any("YAML" in e or "yaml" in e.lower() for e in result["errors"])

    def test_missing_rules_key_warning(self):
        result = validate_policy("version: 1\n")
        # No 'rules' key → warning, not error (still valid)
        assert result["valid"] is True
        assert any("rules" in w.lower() for w in result["warnings"])

    def test_invalid_action_value(self):
        bad = """
rules:
  - entity_type: SSN
    action: BANANA
"""
        result = validate_policy(bad)
        assert result["valid"] is False
        assert any("BANANA" in e for e in result["errors"])

    def test_empty_string_error(self):
        result = validate_policy("")
        # Empty string → yaml.safe_load returns None → not a dict
        assert result["valid"] is False

    def test_large_yaml_validates(self):
        rules = "\n".join(
            f"  - entity_type: TYPE_{i}\n    action: REDACT" for i in range(100)
        )
        big_yaml = f"rules:\n{rules}\n"
        result = validate_policy(big_yaml)
        assert result["valid"] is True

    def test_all_valid_fields_no_warnings(self):
        policy = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
"""
        result = validate_policy(policy)
        assert result["valid"] is True
        # No conflicts = no warnings
        assert len(result["warnings"]) == 0

    def test_validate_yaml_legacy_wrapper(self):
        valid, msg = validate_yaml(SIMPLE_POLICY)
        assert valid is True
        assert "Valid" in msg


# ═══════════════════════════════════════════════════════════════════════
# COMPLIANCE PACKS (5 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestCompliancePacks:
    def test_list_returns_six_plus_packs(self):
        packs = list_compliance_packs()
        assert len(packs) >= 6
        for name in ["GDPR", "HIPAA", "PCI_DSS", "CCPA", "SOX", "EU_AI_ACT"]:
            assert name in packs

    def test_gdpr_pack_has_entity_action_mappings(self):
        pack = get_compliance_pack("GDPR")
        assert pack is not None
        assert "SSN" in pack
        assert pack["SSN"] == "REDACT"
        assert pack["EMAIL"] == "PSEUDONYMIZE"

    def test_hipaa_includes_phi_entities(self):
        pack = get_compliance_pack("HIPAA")
        assert pack is not None
        assert pack["PERSON_NAME"] == "REDACT"
        assert pack["PHONE"] == "REDACT"
        assert pack["EMAIL"] == "REDACT"

    def test_nonexistent_pack_returns_none(self):
        assert get_compliance_pack("NONEXISTENT") is None

    def test_compliance_mapping_for_ssn(self):
        mapping = get_compliance_mapping(["SSN"])
        assert "SSN" in mapping
        assert "GDPR" in mapping["SSN"]
        assert "HIPAA" in mapping["SSN"]
        assert mapping["SSN"]["GDPR"] == "REDACT"


# ═══════════════════════════════════════════════════════════════════════
# POLICY DIFF (5 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestPolicyDiff:
    def test_diff_added_rule(self):
        old = """
rules:
  - entity_type: SSN
    action: REDACT
"""
        new = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
"""
        changes = diff_policies(old, new)
        added = [c for c in changes if c.change_type == "ADDED"]
        assert len(added) >= 1
        assert any(c.entity_type == "EMAIL" for c in added)

    def test_diff_removed_rule(self):
        old = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
"""
        new = """
rules:
  - entity_type: SSN
    action: REDACT
"""
        changes = diff_policies(old, new)
        removed = [c for c in changes if c.change_type == "REMOVED"]
        assert len(removed) >= 1
        assert any(c.entity_type == "EMAIL" for c in removed)

    def test_diff_modified_action(self):
        old = """
rules:
  - entity_type: SSN
    action: REDACT
"""
        new = """
rules:
  - entity_type: SSN
    action: TOKENIZE
"""
        changes = diff_policies(old, new)
        modified = [c for c in changes if c.change_type == "MODIFIED"]
        assert len(modified) >= 1
        assert any(c.entity_type == "SSN" for c in modified)

    def test_diff_identical_policies_empty(self):
        changes = diff_policies(SIMPLE_POLICY, SIMPLE_POLICY)
        assert len(changes) == 0

    def test_diff_multiple_changes(self):
        old = """
rules:
  - entity_type: SSN
    action: REDACT
  - entity_type: EMAIL
    action: TOKENIZE
"""
        new = """
rules:
  - entity_type: SSN
    action: PASS
  - entity_type: PHONE
    action: REDACT
"""
        changes = diff_policies(old, new)
        # SSN modified, EMAIL removed, PHONE added
        types_changed = {c.change_type for c in changes}
        assert "MODIFIED" in types_changed
        assert "REMOVED" in types_changed
        assert "ADDED" in types_changed


# ═══════════════════════════════════════════════════════════════════════
# SIMULATE (3 tests)
# ═══════════════════════════════════════════════════════════════════════

class TestSimulate:
    def test_simulate_with_entities(self):
        entities = [
            {"entity_type": "SSN", "text": "123-45-6789"},
            {"entity_type": "EMAIL", "text": "a@b.com"},
        ]
        results = simulate(SIMPLE_POLICY, entities)
        assert len(results) == 2
        by_type = {r["entity_type"]: r for r in results}
        assert by_type["SSN"]["action"] == "REDACT"
        assert by_type["EMAIL"]["action"] == "PSEUDONYMIZE"

    def test_simulate_no_entities(self):
        results = simulate(SIMPLE_POLICY, [])
        assert results == []

    def test_simulate_applies_policy_rules(self):
        entities = [{"entity_type": "PHONE", "text": "555-1234"}]
        results = simulate(SIMPLE_POLICY, entities)
        assert results[0]["action"] == "TOKENIZE"
        assert results[0]["sample_text"] == "555-1234"
