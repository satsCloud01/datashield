"""YAML-based policy evaluation engine with compliance packs, conflict detection, and simulation."""
from __future__ import annotations

import copy
import yaml
from dataclasses import dataclass, field


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    entity_type: str
    action: str              # REDACT | TOKENIZE | PSEUDONYMIZE | GENERALIZE | ENCRYPT | SYNTHESIZE | MASK | PASS | BLOCK
    reason: str
    compliance_refs: list[str] = field(default_factory=list)
    overridden_by: str | None = None   # e.g. "exception:agent-audit-08" or "role:admin"


@dataclass
class PolicyConflict:
    entity_type: str
    rule_a: dict
    rule_b: dict
    description: str


@dataclass
class PolicyChange:
    entity_type: str
    field: str
    old_value: str | None
    new_value: str | None
    change_type: str   # ADDED | REMOVED | MODIFIED


# ── Data classification levels (strictness order) ───────────────────

CLASSIFICATION_LEVELS = {
    "CONFIDENTIAL": 4,
    "RESTRICTED": 3,
    "INTERNAL": 2,
    "PUBLIC": 1,
}

# Entity default classifications
ENTITY_CLASSIFICATIONS: dict[str, str] = {
    "SSN": "CONFIDENTIAL",
    "CREDIT_CARD": "CONFIDENTIAL",
    "PASSPORT": "CONFIDENTIAL",
    "DRIVERS_LICENSE": "CONFIDENTIAL",
    "API_KEY": "CONFIDENTIAL",
    "IBAN": "RESTRICTED",
    "PERSON_NAME": "RESTRICTED",
    "EMAIL": "RESTRICTED",
    "PHONE": "RESTRICTED",
    "IP_ADDRESS": "INTERNAL",
    "DATE": "PUBLIC",
}

# ── Default actions by entity type ───────────────────────────────────

DEFAULT_ACTIONS: dict[str, str] = {
    "SSN": "REDACT",
    "CREDIT_CARD": "REDACT",
    "EMAIL": "TOKENIZE",
    "PHONE": "TOKENIZE",
    "IP_ADDRESS": "MASK",
    "PERSON_NAME": "TOKENIZE",
    "DATE": "PASS",
    "IBAN": "REDACT",
    "API_KEY": "REDACT",
    "PASSPORT": "REDACT",
    "DRIVERS_LICENSE": "REDACT",
}

# Action strictness for conflict resolution (higher = more restrictive)
_ACTION_STRICTNESS: dict[str, int] = {
    "BLOCK": 7,
    "REDACT": 6,
    "ENCRYPT": 5,
    "TOKENIZE": 4,
    "PSEUDONYMIZE": 3,
    "GENERALIZE": 2,
    "MASK": 2,
    "PASS": 1,
}


# ── Built-in compliance packs ────────────────────────────────────────

COMPLIANCE_PACKS: dict[str, dict[str, str]] = {
    "GDPR": {
        "SSN": "REDACT",
        "CREDIT_CARD": "REDACT",
        "EMAIL": "PSEUDONYMIZE",
        "PHONE": "PSEUDONYMIZE",
        "PERSON_NAME": "PSEUDONYMIZE",
        "IP_ADDRESS": "MASK",
        "IBAN": "REDACT",
        "API_KEY": "REDACT",
        "PASSPORT": "REDACT",
        "DRIVERS_LICENSE": "REDACT",
        "DATE": "GENERALIZE",
    },
    "HIPAA": {
        "SSN": "REDACT",
        "CREDIT_CARD": "REDACT",
        "EMAIL": "REDACT",
        "PHONE": "REDACT",
        "PERSON_NAME": "REDACT",
        "IP_ADDRESS": "REDACT",
        "IBAN": "REDACT",
        "API_KEY": "REDACT",
        "PASSPORT": "REDACT",
        "DRIVERS_LICENSE": "REDACT",
        "DATE": "GENERALIZE",
    },
    "PCI_DSS": {
        "CREDIT_CARD": "REDACT",
        "IBAN": "REDACT",
        "API_KEY": "REDACT",
        "SSN": "TOKENIZE",
        "EMAIL": "TOKENIZE",
        "PHONE": "TOKENIZE",
        "PERSON_NAME": "TOKENIZE",
        "IP_ADDRESS": "MASK",
        "PASSPORT": "REDACT",
        "DRIVERS_LICENSE": "REDACT",
        "DATE": "PASS",
    },
    "CCPA": {
        "SSN": "REDACT",
        "CREDIT_CARD": "REDACT",
        "EMAIL": "TOKENIZE",
        "PHONE": "TOKENIZE",
        "PERSON_NAME": "PSEUDONYMIZE",
        "IP_ADDRESS": "MASK",
        "IBAN": "REDACT",
        "API_KEY": "REDACT",
        "PASSPORT": "REDACT",
        "DRIVERS_LICENSE": "REDACT",
        "DATE": "PASS",
    },
    "SOX": {
        "SSN": "REDACT",
        "CREDIT_CARD": "REDACT",
        "EMAIL": "TOKENIZE",
        "PHONE": "TOKENIZE",
        "PERSON_NAME": "TOKENIZE",
        "IP_ADDRESS": "TOKENIZE",
        "IBAN": "REDACT",
        "API_KEY": "REDACT",
        "PASSPORT": "REDACT",
        "DRIVERS_LICENSE": "REDACT",
        "DATE": "PASS",
    },
    "EU_AI_ACT": {
        "SSN": "REDACT",
        "CREDIT_CARD": "REDACT",
        "EMAIL": "PSEUDONYMIZE",
        "PHONE": "PSEUDONYMIZE",
        "PERSON_NAME": "PSEUDONYMIZE",
        "IP_ADDRESS": "PSEUDONYMIZE",
        "IBAN": "REDACT",
        "API_KEY": "REDACT",
        "PASSPORT": "REDACT",
        "DRIVERS_LICENSE": "REDACT",
        "DATE": "GENERALIZE",
    },
}


# ── Helpers ──────────────────────────────────────────────────────────

def _parse_policy(yaml_content: str | None) -> dict | None:
    """Safely parse YAML policy. Returns dict or None."""
    if not yaml_content:
        return None
    try:
        doc = yaml.safe_load(yaml_content)
        return doc if isinstance(doc, dict) else None
    except yaml.YAMLError:
        return None


def _most_restrictive(action_a: str, action_b: str) -> str:
    """Return the more restrictive of two actions."""
    sa = _ACTION_STRICTNESS.get(action_a.upper(), 4)
    sb = _ACTION_STRICTNESS.get(action_b.upper(), 4)
    return action_a if sa >= sb else action_b


def _get_compliance_refs(entity_type: str, action: str, packs: list[str]) -> list[str]:
    """Find which compliance packs require this action or stricter for this entity."""
    refs = []
    for pack_name in packs:
        pack = COMPLIANCE_PACKS.get(pack_name, COMPLIANCE_PACKS.get(pack_name.replace("-", "_"), {}))
        if entity_type in pack:
            pack_action = pack[entity_type]
            pack_strict = _ACTION_STRICTNESS.get(pack_action, 4)
            action_strict = _ACTION_STRICTNESS.get(action, 4)
            if action_strict >= pack_strict:
                refs.append(f"{pack_name}: {pack_action} required")
    return refs


# ── Core evaluation ──────────────────────────────────────────────────

def evaluate(
    policy_yaml: str | None,
    entity_types: list[str],
    agent_id: str | None = None,
    agent_role: str | None = None,
) -> list[PolicyDecision]:
    """Evaluate policy against detected entities. Returns a decision per entity type.

    Implements default-deny: unknown entities/agents get the most restrictive action (REDACT).
    """
    doc = _parse_policy(policy_yaml)

    # Extract rules, exceptions, and role bindings
    rules: list[dict] = []
    exceptions: list[dict] = []
    compliance_packs: list[str] = []

    if doc:
        rules = doc.get("rules", [])
        exceptions = doc.get("exceptions", [])
        compliance_packs = doc.get("compliance_packs", [])
        if isinstance(compliance_packs, str):
            compliance_packs = [compliance_packs]

    # Build overrides from rules
    overrides: dict[str, dict] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        etype = rule.get("entity_type")
        action = rule.get("action", "REDACT").upper()
        roles = rule.get("roles")
        classification = rule.get("classification")

        # Role matching: if rule specifies roles, agent_role must match
        if roles and agent_role and agent_role not in roles:
            continue

        if etype:
            overrides[etype] = {
                "action": action,
                "roles": roles,
                "classification": classification,
                "source": "policy_rule",
            }

    # Check exceptions
    exception_overrides: dict[str, str] = {}
    for exc in exceptions:
        if not isinstance(exc, dict):
            continue
        exc_agent = exc.get("agent_id")
        exc_role = exc.get("agent_role")
        exc_entities = exc.get("entity_types", [])
        exc_action = exc.get("action", "PASS").upper()

        matched = False
        if exc_agent and agent_id and exc_agent == agent_id:
            matched = True
        if exc_role and agent_role and exc_role == agent_role:
            matched = True

        if matched:
            for et in exc_entities:
                exception_overrides[et] = exc_action

    # Build decisions
    results: list[PolicyDecision] = []
    for etype in entity_types:
        overridden_by = None

        # Check exception first
        if etype in exception_overrides:
            action = exception_overrides[etype]
            overridden_by = f"exception:{agent_id or agent_role}"
            reason = f"Exception granted for {agent_id or agent_role}"
        elif etype in overrides:
            action = overrides[etype]["action"]
            reason = f"Policy rule for {etype}"
        elif etype in DEFAULT_ACTIONS:
            action = DEFAULT_ACTIONS[etype]
            reason = "Default policy"
        else:
            # Default deny: unknown entity types get REDACT
            action = "REDACT"
            reason = "Default deny — unknown entity type"

        comp_refs = _get_compliance_refs(etype, action, compliance_packs)

        results.append(PolicyDecision(
            entity_type=etype,
            action=action,
            reason=reason,
            compliance_refs=comp_refs,
            overridden_by=overridden_by,
        ))

    return results


# ── Legacy compatibility ─────────────────────────────────────────────

def evaluate_policy(yaml_content: str | None, entity_types: list[str], agent_role: str | None = None) -> list[PolicyDecision]:
    """Legacy wrapper for backward compatibility."""
    return evaluate(yaml_content, entity_types, agent_role=agent_role)


# ── Conflict detection ───────────────────────────────────────────────

def detect_conflicts(policy_yaml: str) -> list[PolicyConflict]:
    """Detect conflicting rules in a policy (e.g., same entity with different actions for overlapping roles)."""
    doc = _parse_policy(policy_yaml)
    if not doc:
        return []

    rules = doc.get("rules", [])
    conflicts: list[PolicyConflict] = []

    # Group rules by entity_type
    by_entity: dict[str, list[dict]] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        etype = rule.get("entity_type")
        if etype:
            by_entity.setdefault(etype, []).append(rule)

    for etype, entity_rules in by_entity.items():
        if len(entity_rules) < 2:
            continue
        for i in range(len(entity_rules)):
            for j in range(i + 1, len(entity_rules)):
                ra, rb = entity_rules[i], entity_rules[j]
                action_a = ra.get("action", "REDACT").upper()
                action_b = rb.get("action", "REDACT").upper()
                if action_a == action_b:
                    continue
                roles_a = set(ra.get("roles", []) or [])
                roles_b = set(rb.get("roles", []) or [])
                # Conflict if roles overlap or either has no role restriction
                if not roles_a or not roles_b or roles_a & roles_b:
                    conflicts.append(PolicyConflict(
                        entity_type=etype,
                        rule_a=ra,
                        rule_b=rb,
                        description=f"{etype}: conflicting actions {action_a} vs {action_b}"
                        + (f" for overlapping roles {roles_a & roles_b}" if roles_a and roles_b and roles_a & roles_b else ""),
                    ))

    return conflicts


# ── Policy simulation ────────────────────────────────────────────────

def simulate(policy_yaml: str, sample_entities: list[dict]) -> list[dict]:
    """Simulate what would happen to a list of entities under a policy.

    sample_entities: [{"entity_type": "SSN", "text": "123-45-6789"}, ...]
    Returns list of dicts with entity info + decision.
    """
    entity_types = [e.get("entity_type", "UNKNOWN") for e in sample_entities]
    decisions = evaluate(policy_yaml, entity_types)

    results = []
    for entity, decision in zip(sample_entities, decisions):
        results.append({
            "entity_type": entity.get("entity_type"),
            "sample_text": entity.get("text", ""),
            "action": decision.action,
            "reason": decision.reason,
            "compliance_refs": decision.compliance_refs,
        })
    return results


# ── Compliance mapping ───────────────────────────────────────────────

def get_compliance_mapping(entity_types: list[str]) -> dict[str, dict[str, str]]:
    """For each entity type, return what each compliance pack requires."""
    result: dict[str, dict[str, str]] = {}
    for etype in entity_types:
        result[etype] = {}
        for pack_name, pack_rules in COMPLIANCE_PACKS.items():
            if etype in pack_rules:
                result[etype][pack_name] = pack_rules[etype]
            else:
                result[etype][pack_name] = "N/A"
    return result


def get_compliance_pack(pack_name: str) -> dict[str, str] | None:
    """Return a specific compliance pack's entity-action mappings."""
    normalized = pack_name.upper().replace("-", "_").replace(" ", "_")
    return COMPLIANCE_PACKS.get(normalized)


def list_compliance_packs() -> list[str]:
    """Return names of all built-in compliance packs."""
    return list(COMPLIANCE_PACKS.keys())


# ── Validation ───────────────────────────────────────────────────────

def validate_policy(yaml_str: str) -> dict:
    """Validate a YAML policy string. Returns {valid: bool, errors: list, warnings: list}."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        doc = yaml.safe_load(yaml_str)
    except yaml.YAMLError as e:
        return {"valid": False, "errors": [f"Invalid YAML: {e}"], "warnings": []}

    if not isinstance(doc, dict):
        return {"valid": False, "errors": ["Root element must be a mapping"], "warnings": []}

    # Check for rules
    rules = doc.get("rules")
    if rules is None:
        warnings.append("No 'rules' key found — all entities will use default actions")
    elif not isinstance(rules, list):
        errors.append("'rules' must be a list")
    else:
        valid_actions = set(_ACTION_STRICTNESS.keys())
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i}: must be a mapping")
                continue
            if "entity_type" not in rule:
                errors.append(f"Rule {i}: missing 'entity_type'")
            action = rule.get("action", "").upper()
            if action and action not in valid_actions:
                errors.append(f"Rule {i}: unknown action '{action}'. Valid: {sorted(valid_actions)}")
            roles = rule.get("roles")
            if roles is not None and not isinstance(roles, list):
                errors.append(f"Rule {i}: 'roles' must be a list")

    # Check exceptions
    exceptions = doc.get("exceptions")
    if exceptions is not None:
        if not isinstance(exceptions, list):
            errors.append("'exceptions' must be a list")
        else:
            for i, exc in enumerate(exceptions):
                if not isinstance(exc, dict):
                    errors.append(f"Exception {i}: must be a mapping")
                    continue
                if "agent_id" not in exc and "agent_role" not in exc:
                    warnings.append(f"Exception {i}: no agent_id or agent_role specified — will never match")

    # Check conflicts
    if not errors:
        conflicts = detect_conflicts(yaml_str)
        for c in conflicts:
            warnings.append(f"Conflict: {c.description}")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


# Legacy wrapper
def validate_yaml(content: str) -> tuple[bool, str]:
    """Legacy validation. Returns (is_valid, message)."""
    result = validate_policy(content)
    if result["valid"]:
        msg = "Valid policy YAML"
        if result["warnings"]:
            msg += f" ({len(result['warnings'])} warnings)"
        return True, msg
    return False, "; ".join(result["errors"])


# ── Policy diff ──────────────────────────────────────────────────────

def diff_policies(old_yaml: str, new_yaml: str) -> list[PolicyChange]:
    """Compare two policy YAMLs and return a list of changes."""
    old_doc = _parse_policy(old_yaml) or {}
    new_doc = _parse_policy(new_yaml) or {}

    old_rules: dict[str, dict] = {}
    new_rules: dict[str, dict] = {}

    for rule in old_doc.get("rules", []):
        if isinstance(rule, dict) and "entity_type" in rule:
            old_rules[rule["entity_type"]] = rule

    for rule in new_doc.get("rules", []):
        if isinstance(rule, dict) and "entity_type" in rule:
            new_rules[rule["entity_type"]] = rule

    changes: list[PolicyChange] = []

    all_types = set(old_rules.keys()) | set(new_rules.keys())
    for etype in sorted(all_types):
        if etype not in old_rules:
            changes.append(PolicyChange(
                entity_type=etype, field="rule",
                old_value=None, new_value=str(new_rules[etype]),
                change_type="ADDED",
            ))
        elif etype not in new_rules:
            changes.append(PolicyChange(
                entity_type=etype, field="rule",
                old_value=str(old_rules[etype]), new_value=None,
                change_type="REMOVED",
            ))
        else:
            old_r, new_r = old_rules[etype], new_rules[etype]
            for key in set(list(old_r.keys()) + list(new_r.keys())):
                if key == "entity_type":
                    continue
                old_v = old_r.get(key)
                new_v = new_r.get(key)
                if old_v != new_v:
                    changes.append(PolicyChange(
                        entity_type=etype, field=key,
                        old_value=str(old_v) if old_v is not None else None,
                        new_value=str(new_v) if new_v is not None else None,
                        change_type="MODIFIED",
                    ))

    # Check top-level fields
    for field_name in ["version", "retention_days", "audit", "right_to_erasure"]:
        old_v = old_doc.get(field_name)
        new_v = new_doc.get(field_name)
        if old_v != new_v:
            ct = "ADDED" if old_v is None else ("REMOVED" if new_v is None else "MODIFIED")
            changes.append(PolicyChange(
                entity_type="*", field=field_name,
                old_value=str(old_v) if old_v is not None else None,
                new_value=str(new_v) if new_v is not None else None,
                change_type=ct,
            ))

    return changes
