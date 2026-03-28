"""In-memory reversible tokenisation vault with 6 obfuscation modes and session lifecycle."""
from __future__ import annotations

import base64
import hashlib
import random
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from datashield.services.detection_engine import Detection


# ── Obfuscation modes ────────────────────────────────────────────────

class ObfuscationMode(str, Enum):
    REDACT = "REDACT"
    TOKENIZE = "TOKENIZE"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    GENERALIZE = "GENERALIZE"
    ENCRYPT = "ENCRYPT"
    SYNTHESIZE = "SYNTHESIZE"


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class VaultEntry:
    original_text: str
    sanitized_text: str
    mappings: dict[str, str]        # token/replacement -> original
    mode: str
    created_at: float


@dataclass
class VaultSession:
    session_id: str
    agent_id: str
    policy_id: str
    created_at: float
    ttl_seconds: int
    entries: dict[str, VaultEntry] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    pseudo_cache: dict[str, str] = field(default_factory=dict)  # deterministic pseudonyms


# ── Pseudonymization pools ───────────────────────────────────────────

_FAKE_NAMES = [
    "Alex Morgan", "Jordan Lee", "Taylor Brooks", "Casey Quinn", "Robin Park",
    "Dana Wells", "Morgan Reed", "Riley Stone", "Avery Grant", "Blake Foster",
    "Harper Cole", "Skyler Dunn", "Jamie West", "Quinn Torres", "Sage Murray",
    "Drew Pearson", "Finley Hart", "Rowan Blake", "Emery Chase", "Logan Reeves",
]

_FAKE_EMAILS = [
    "user_alpha@example.com", "user_beta@example.net", "user_gamma@example.org",
    "user_delta@sample.com", "user_epsilon@demo.net", "user_zeta@test.org",
    "user_eta@mock.com", "user_theta@fake.net", "user_iota@dummy.org",
    "user_kappa@proxy.com",
]

_FAKE_PHONES = [
    "(555) 100-0001", "(555) 200-0002", "(555) 300-0003", "(555) 400-0004",
    "(555) 500-0005", "(555) 600-0006", "(555) 700-0007", "(555) 800-0008",
]

_FAKE_SSNS = [
    "000-00-0001", "000-00-0002", "000-00-0003", "000-00-0004",
    "000-00-0005", "000-00-0006", "000-00-0007", "000-00-0008",
]

_FAKE_POOLS: dict[str, list[str]] = {
    "PERSON_NAME": _FAKE_NAMES,
    "EMAIL": _FAKE_EMAILS,
    "PHONE": _FAKE_PHONES,
    "SSN": _FAKE_SSNS,
}

# ── Generalization rules ─────────────────────────────────────────────

def _generalize_value(entity_type: str, text: str) -> str:
    """Replace exact values with categorical generalizations."""
    t = entity_type.upper()
    if t == "DATE":
        # Try to extract year/month
        for sep in ["-", "/"]:
            parts = text.split(sep)
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1] if len(parts[0]) == 4 else parts[0]}" + " (month)"
        return "[DATE_RANGE]"
    if t in ("SSN", "PASSPORT", "DRIVERS_LICENSE"):
        return f"[{t}_GENERALIZED]"
    if t == "CREDIT_CARD":
        return "****-****-****-" + text[-4:] if len(text) >= 4 else "[CARD_GENERALIZED]"
    if t == "PHONE":
        return "(***) ***-" + text[-4:] if len(text) >= 4 else "[PHONE_GENERALIZED]"
    if t == "EMAIL":
        if "@" in text:
            domain = text.split("@")[1]
            return f"***@{domain}"
        return "[EMAIL_GENERALIZED]"
    if t == "IP_ADDRESS":
        parts = text.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0/16"
        return "[IP_GENERALIZED]"
    if t == "PERSON_NAME":
        return "[PERSON]"
    if t == "IBAN":
        return text[:4] + "****" + text[-4:] if len(text) >= 8 else "[IBAN_GENERALIZED]"
    if t == "API_KEY":
        return text[:4] + "..." if len(text) >= 4 else "[KEY_GENERALIZED]"
    return f"[{t}_GENERALIZED]"


def _synthesize_value(entity_type: str, _text: str) -> str:
    """Generate realistic-looking fake data."""
    t = entity_type.upper()
    r = random.Random()  # non-deterministic for synthesis
    if t == "PERSON_NAME":
        first = random.choice(["James", "Maria", "Chen", "Aisha", "Raj", "Elena", "Yuki", "Omar"])
        last = random.choice(["Smith", "Garcia", "Wang", "Okafor", "Patel", "Novak", "Tanaka", "Hassan"])
        return f"{first} {last}"
    if t == "EMAIL":
        user = f"user{r.randint(1000, 9999)}"
        domain = random.choice(["example.com", "sample.org", "demo.net"])
        return f"{user}@{domain}"
    if t == "PHONE":
        return f"({r.randint(200,999)}) {r.randint(100,999)}-{r.randint(1000,9999)}"
    if t == "SSN":
        return f"{r.randint(100,999)}-{r.randint(10,99)}-{r.randint(1000,9999)}"
    if t == "CREDIT_CARD":
        return f"{r.randint(4000,4999)}-{r.randint(1000,9999)}-{r.randint(1000,9999)}-{r.randint(1000,9999)}"
    if t == "IP_ADDRESS":
        return f"{r.randint(10,192)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"
    if t == "IBAN":
        return f"XX{r.randint(10,99)}BANK{r.randint(10000000,99999999)}"
    if t == "API_KEY":
        return f"sk-fake-{''.join(random.choices('abcdef0123456789', k=16))}"
    if t == "DATE":
        return f"2025-{r.randint(1,12):02d}-{r.randint(1,28):02d}"
    if t == "PASSPORT":
        return f"X{r.randint(10000000,99999999)}"
    if t == "DRIVERS_LICENSE":
        return f"D{r.randint(1000,9999)} {r.randint(1000,9999)} {r.randint(10000,99999)}"
    return f"[SYNTH_{t}]"


def _encrypt_value(text: str, session_id: str) -> str:
    """Format-preserving base64 encoding (reversible with session context)."""
    key_material = f"{session_id}:{text}".encode()
    encoded = base64.urlsafe_b64encode(key_material).decode().rstrip("=")
    return f"ENC:{encoded}"


def _decrypt_value(encrypted: str, _session_id: str) -> str | None:
    """Reverse format-preserving base64 encoding."""
    if not encrypted.startswith("ENC:"):
        return None
    encoded = encrypted[4:]
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(encoded).decode()
        # Format is session_id:original_text
        if ":" in decoded:
            return decoded.split(":", 1)[1]
    except Exception:
        pass
    return None


# ── In-memory stores ─────────────────────────────────────────────────

_sessions: dict[str, VaultSession] = {}


# ── Session management ───────────────────────────────────────────────

def create_session(agent_id: str, policy_id: str, ttl_seconds: int = 1800) -> str:
    """Create a new vault session. Returns session_id."""
    session_id = f"vs_{uuid.uuid4().hex[:12]}"
    _sessions[session_id] = VaultSession(
        session_id=session_id,
        agent_id=agent_id,
        policy_id=policy_id,
        created_at=time.time(),
        ttl_seconds=ttl_seconds,
    )
    return session_id


def _is_expired(session: VaultSession) -> bool:
    return time.time() > session.created_at + session.ttl_seconds


def get_session(session_id: str) -> dict | None:
    """Return session info dict or None if not found."""
    s = _sessions.get(session_id)
    if s is None:
        return None
    return {
        "session_id": s.session_id,
        "agent_id": s.agent_id,
        "policy_id": s.policy_id,
        "created_at": s.created_at,
        "ttl_seconds": s.ttl_seconds,
        "expired": _is_expired(s),
        "entries_count": len(s.entries),
        "total_tokens": sum(len(e.mappings) for e in s.entries.values()),
    }


def list_sessions() -> list[dict]:
    """Return info for all sessions."""
    results = []
    for sid in _sessions:
        info = get_session(sid)
        if info:
            results.append(info)
    return results


def purge_session(session_id: str) -> bool:
    """Remove a session and all its vault entries. Returns True if found."""
    if session_id in _sessions:
        del _sessions[session_id]
        return True
    return False


def get_session_stats(session_id: str) -> dict | None:
    """Return detailed stats for a session."""
    s = _sessions.get(session_id)
    if s is None:
        return None
    tokens_by_type: dict[str, int] = {}
    modes_used: dict[str, int] = {}
    for entry in s.entries.values():
        modes_used[entry.mode] = modes_used.get(entry.mode, 0) + 1
        for token_key in entry.mappings:
            # Extract type from token keys like <<TYPE_N>>
            for etype in ["SSN", "EMAIL", "PHONE", "CREDIT_CARD", "IP_ADDRESS",
                          "PERSON_NAME", "IBAN", "API_KEY", "DATE", "PASSPORT", "DRIVERS_LICENSE"]:
                if etype in token_key.upper() or etype in str(token_key):
                    tokens_by_type[etype] = tokens_by_type.get(etype, 0) + 1
                    break
    return {
        "session_id": s.session_id,
        "agent_id": s.agent_id,
        "policy_id": s.policy_id,
        "expired": _is_expired(s),
        "entries_count": len(s.entries),
        "total_tokens": sum(len(e.mappings) for e in s.entries.values()),
        "tokens_by_type": tokens_by_type,
        "modes_used": modes_used,
        "age_seconds": round(time.time() - s.created_at, 1),
        "ttl_remaining": max(0, round(s.created_at + s.ttl_seconds - time.time(), 1)),
    }


# ── Vault stats ──────────────────────────────────────────────────────

def get_vault_stats() -> dict:
    """Return aggregate vault statistics."""
    total_tokens = 0
    tokens_by_type: dict[str, int] = {}
    active = 0
    for s in _sessions.values():
        if not _is_expired(s):
            active += 1
        for entry in s.entries.values():
            total_tokens += len(entry.mappings)
            for token_key in entry.mappings:
                for etype in ["SSN", "EMAIL", "PHONE", "CREDIT_CARD", "IP_ADDRESS",
                              "PERSON_NAME", "IBAN", "API_KEY", "DATE", "PASSPORT", "DRIVERS_LICENSE"]:
                    if etype in str(token_key).upper():
                        tokens_by_type[etype] = tokens_by_type.get(etype, 0) + 1
                        break
    return {
        "total_sessions": len(_sessions),
        "active_sessions": active,
        "expired_sessions": len(_sessions) - active,
        "total_tokens": total_tokens,
        "tokens_by_type": tokens_by_type,
    }


# ── Pseudonymization helper ──────────────────────────────────────────

def _pseudonymize_value(session: VaultSession, entity_type: str, text: str) -> str:
    """Return a deterministic fake value — same input always maps to same output within a session."""
    cache_key = f"{entity_type}:{text}"
    if cache_key in session.pseudo_cache:
        return session.pseudo_cache[cache_key]

    pool = _FAKE_POOLS.get(entity_type)
    if pool:
        # Hash-based deterministic selection
        h = int(hashlib.sha256(f"{session.session_id}:{cache_key}".encode()).hexdigest(), 16)
        fake = pool[h % len(pool)]
    else:
        # Generic pseudonym
        h = int(hashlib.sha256(f"{session.session_id}:{cache_key}".encode()).hexdigest(), 16)
        fake = f"[PSEUDO_{entity_type}_{h % 10000:04d}]"

    session.pseudo_cache[cache_key] = fake
    return fake


# ── Core tokenization ────────────────────────────────────────────────

def _apply_mode(session: VaultSession, entity_type: str, text: str, mode: ObfuscationMode, counter: int) -> str:
    """Apply the chosen obfuscation mode to a single entity value."""
    if mode == ObfuscationMode.REDACT:
        return "[REDACTED]"
    elif mode == ObfuscationMode.TOKENIZE:
        return f"<<{entity_type}_{counter}>>"
    elif mode == ObfuscationMode.PSEUDONYMIZE:
        return _pseudonymize_value(session, entity_type, text)
    elif mode == ObfuscationMode.GENERALIZE:
        return _generalize_value(entity_type, text)
    elif mode == ObfuscationMode.ENCRYPT:
        return _encrypt_value(text, session.session_id)
    elif mode == ObfuscationMode.SYNTHESIZE:
        return _synthesize_value(entity_type, text)
    else:
        return f"<<{entity_type}_{counter}>>"


def tokenize(
    session_id: str,
    text: str,
    detections: list[Detection],
    mode: str = "TOKENIZE",
) -> tuple[str, str]:
    """Replace detected spans with obfuscated values. Returns (sanitized_text, vault_ref).

    Raises ValueError if session not found or expired.
    """
    session = _sessions.get(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    if _is_expired(session):
        raise ValueError(f"Session {session_id} has expired")

    try:
        obfuscation_mode = ObfuscationMode(mode.upper())
    except ValueError:
        obfuscation_mode = ObfuscationMode.TOKENIZE

    vault_ref = f"vlt_{uuid.uuid4().hex[:12]}"
    mappings: dict[str, str] = {}

    # Process detections end-to-start to keep indices valid
    sorted_dets = sorted(detections, key=lambda d: d.start, reverse=True)
    result = text

    for det in sorted_dets:
        session.counters.setdefault(det.entity_type, 0)
        session.counters[det.entity_type] += 1
        counter = session.counters[det.entity_type]

        replacement = _apply_mode(session, det.entity_type, det.text, obfuscation_mode, counter)
        mappings[replacement] = det.text
        result = result[:det.start] + replacement + result[det.end:]

    entry = VaultEntry(
        original_text=text,
        sanitized_text=result,
        mappings=mappings,
        mode=obfuscation_mode.value,
        created_at=time.time(),
    )
    session.entries[vault_ref] = entry

    return result, vault_ref


def restore(vault_ref: str) -> tuple[str, int] | None:
    """Restore original text from vault ref. Returns (original_text, token_count) or None.

    Searches all sessions for the vault_ref. Rejects if session is expired.
    """
    for session in _sessions.values():
        entry = session.entries.get(vault_ref)
        if entry is not None:
            if _is_expired(session):
                return None  # expired session — deny access
            return entry.original_text, len(entry.mappings)
    return None


def get_entry(vault_ref: str) -> VaultEntry | None:
    """Retrieve a vault entry by ref across all sessions."""
    for session in _sessions.values():
        entry = session.entries.get(vault_ref)
        if entry is not None:
            if _is_expired(session):
                return None
            return entry
    return None


# ── Legacy compatibility (session-less, creates ephemeral session) ───

def tokenize_simple(text: str, detections: list[Detection]) -> tuple[str, str]:
    """Legacy API: auto-creates an ephemeral session for backward compatibility."""
    sid = create_session(agent_id="legacy", policy_id="default", ttl_seconds=3600)
    return tokenize(sid, text, detections, mode="TOKENIZE")
