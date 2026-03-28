"""
Exhaustive multi-stage PII / PHI / PCI / Financial / IP-Code / Custom
entity detection engine with context-aware confidence scoring.

50+ entity types  ·  4-stage pipeline  ·  Luhn validation  ·  dynamic confidence
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ────────────────────────────────────────────────────────────────────

class Category(str, Enum):
    PII = "PII"
    PHI = "PHI"
    PCI = "PCI"
    FINANCIAL = "FINANCIAL"
    IP_CODE = "IP_CODE"
    CUSTOM = "CUSTOM"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DefaultAction(str, Enum):
    REDACT = "REDACT"
    TOKENIZE = "TOKENIZE"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    GENERALIZE = "GENERALIZE"


# ── Detection dataclass (backward-compatible) ───────────────────────────────

@dataclass
class Detection:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    category: str = ""
    regulatory_basis: str = ""
    default_action: str = ""
    risk_level: str = ""


# ── Entity descriptor ───────────────────────────────────────────────────────

@dataclass
class _EntityDef:
    entity_type: str
    category: Category
    pattern: re.Pattern
    base_confidence: float
    regulatory_basis: str
    default_action: DefaultAction
    risk_level: RiskLevel
    format_strict: bool = True          # exact format = 1.0, else 0.85
    context_keywords: list[str] = field(default_factory=list)


# ── Luhn algorithm ──────────────────────────────────────────────────────────

def validate_luhn(number: str) -> bool:
    """Return True if *number* (digits only) passes the Luhn check."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 2:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Master entity registry (50+ types) ──────────────────────────────────────

_ENTITY_DEFS: list[_EntityDef] = []

def _e(entity_type: str, category: Category, pattern: str, base_confidence: float,
       regulatory_basis: str, default_action: DefaultAction, risk_level: RiskLevel,
       format_strict: bool = True, context_keywords: list[str] | None = None,
       flags: int = 0):
    _ENTITY_DEFS.append(_EntityDef(
        entity_type=entity_type,
        category=category,
        pattern=re.compile(pattern, flags),
        base_confidence=base_confidence,
        regulatory_basis=regulatory_basis,
        default_action=default_action,
        risk_level=risk_level,
        format_strict=format_strict,
        context_keywords=context_keywords or [],
    ))


# ─── PII (16 types) ─────────────────────────────────────────────────────────

_e("FULL_NAME", Category.PII,
   r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Rev|Capt|Sgt|Hon)\.?\s+[A-Z][a-z]{1,20}(?:\s+(?:[A-Z]\.?\s+)?[A-Z][a-z]{1,20}){1,2}\b",
   0.75, "GDPR Art.4(1)", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   format_strict=False,
   context_keywords=["name", "patient", "employee", "customer", "applicant", "client", "user"])

_e("EMAIL", Category.PII,
   r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b",
   0.97, "GDPR Art.4(1)", DefaultAction.PSEUDONYMIZE, RiskLevel.HIGH,
   context_keywords=["email", "e-mail", "contact", "address", "mailto"])

_e("PHONE", Category.PII,
   r"(?<!\d)(?:\+?1[\s\-.]?)?\(?[2-9]\d{2}\)?[\s\-.]?[2-9]\d{2}[\s\-.]?\d{4}(?!\d)",
   0.85, "GDPR Art.4(1)", DefaultAction.REDACT, RiskLevel.MEDIUM,
   context_keywords=["phone", "tel", "cell", "mobile", "fax", "call", "contact"])

_e("SSN", Category.PII,
   r"(?<!\d)(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)",
   0.96, "HIPAA §164.514(b), CCPA §1798.140", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["ssn", "social security", "social sec", "tax id", "taxpayer"])

_e("PASSPORT_NO", Category.PII,
   r"\b[A-Z]{1,2}\d{6,9}\b",
   0.60, "GDPR Art.4(1), ICAO Doc 9303", DefaultAction.REDACT, RiskLevel.HIGH,
   format_strict=False,
   context_keywords=["passport", "travel document", "passport number", "passport no"])

_e("DRIVERS_LICENSE", Category.PII,
   r"\b[A-Z]\d{4}[\s\-]?\d{4}[\s\-]?\d{4,5}\b",
   0.68, "GDPR Art.4(1), CCPA §1798.140", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["driver", "license", "licence", "dl", "driving"])

_e("IP_ADDRESS", Category.PII,
   r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
   0.88, "GDPR Art.4(1), Recital 30", DefaultAction.GENERALIZE, RiskLevel.MEDIUM,
   context_keywords=["ip", "address", "host", "server", "client", "source", "origin"])

_e("DATE_OF_BIRTH", Category.PII,
   r"\b(?:(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}|(?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01]))\b",
   0.82, "GDPR Art.4(1), HIPAA §164.514", DefaultAction.GENERALIZE, RiskLevel.MEDIUM,
   context_keywords=["dob", "birth", "born", "birthday", "date of birth"])

_e("MAC_ADDRESS", Category.PII,
   r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
   0.92, "GDPR Recital 30", DefaultAction.GENERALIZE, RiskLevel.MEDIUM,
   context_keywords=["mac", "hardware", "device", "network", "interface", "adapter"])

_e("VIN", Category.PII,
   r"\b[A-HJ-NPR-Z0-9]{17}\b",
   0.55, "CCPA §1798.140", DefaultAction.PSEUDONYMIZE, RiskLevel.LOW,
   format_strict=False,
   context_keywords=["vin", "vehicle", "car", "automobile", "chassis"])

_e("NATIONAL_ID", Category.PII,
   r"\b\d{3}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{2}\b",
   0.60, "GDPR Art.87", DefaultAction.REDACT, RiskLevel.HIGH,
   format_strict=False,
   context_keywords=["national id", "identity card", "id number", "citizen"])

_e("TAX_ID", Category.PII,
   r"\b\d{2}-\d{7}\b",
   0.72, "GDPR Art.4(1), IRS Pub 1635", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["ein", "tax id", "tin", "taxpayer", "employer identification"])

_e("BIOMETRIC_ID", Category.PII,
   r"\b(?:BIO|BIOM)[_\-]?[A-Z0-9]{8,20}\b",
   0.80, "GDPR Art.9(1), BIPA §15", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["biometric", "fingerprint", "retina", "iris", "facial", "voice print"])

_e("COOKIE_ID", Category.PII,
   r"\b(?:_ga|_fbp|_gcl_aw|ajs_anonymous_id|amplitude_id)=[\w\-\.]{10,80}\b",
   0.90, "GDPR Recital 30, ePrivacy Dir Art.5(3)", DefaultAction.REDACT, RiskLevel.MEDIUM,
   context_keywords=["cookie", "tracker", "analytics", "tracking"])

_e("DEVICE_ID", Category.PII,
   r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
   0.70, "GDPR Recital 30", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   format_strict=False,
   context_keywords=["device", "uuid", "guid", "identifier", "id"])

_e("USERNAME", Category.PII,
   r"(?<=@)[A-Za-z_][A-Za-z0-9_.]{2,30}\b",
   0.60, "GDPR Art.4(1)", DefaultAction.PSEUDONYMIZE, RiskLevel.LOW,
   format_strict=False,
   context_keywords=["user", "username", "handle", "account", "login", "screen name"])

# ─── PHI (10 types) ─────────────────────────────────────────────────────────

_e("PATIENT_ID", Category.PHI,
   r"\b(?:PAT|PT)[_\-]?\d{6,12}\b",
   0.92, "HIPAA §164.514(b)(2)", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["patient", "pt", "subject", "enrollee"])

_e("MRN", Category.PHI,
   r"\b(?:MRN|MR)[_\-:#]?\s?\d{5,12}\b",
   0.93, "HIPAA §164.514(b)(2)", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["mrn", "medical record", "record number", "chart"])

_e("DIAGNOSIS_CODE", Category.PHI,
   r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b",
   0.55, "HIPAA §164.514, ICD-10-CM", DefaultAction.GENERALIZE, RiskLevel.HIGH,
   format_strict=False,
   context_keywords=["icd", "diagnosis", "dx", "condition", "disease", "disorder"])

_e("MEDICATION_NAME", Category.PHI,
   r"\b(?:Metformin|Lisinopril|Atorvastatin|Amoxicillin|Omeprazole|Losartan|Amlodipine|Simvastatin|Gabapentin|Hydrochlorothiazide|Sertraline|Pantoprazole|Metoprolol|Atenolol|Prednisone|Furosemide|Warfarin|Insulin|Clopidogrel|Levothyroxine|Acetaminophen|Ibuprofen|Aspirin|Montelukast|Albuterol|Tamsulosin|Alprazolam|Duloxetine|Escitalopram|Fluoxetine|Citalopram|Bupropion|Trazodone|Tramadol|Oxycodone|Morphine|Fentanyl|Diazepam|Lorazepam|Clonazepam)\b",
   0.88, "HIPAA §164.514(b)", DefaultAction.GENERALIZE, RiskLevel.MEDIUM,
   flags=re.IGNORECASE,
   context_keywords=["medication", "drug", "rx", "prescription", "dose", "medicine", "pharma"])

_e("PROVIDER_NPI", Category.PHI,
   r"\b(?:NPI[:\s#]?)?\d{10}\b",
   0.60, "HIPAA §164.514, 45 CFR 162.406", DefaultAction.PSEUDONYMIZE, RiskLevel.HIGH,
   format_strict=False,
   context_keywords=["npi", "provider", "physician", "doctor", "practitioner", "clinician"])

_e("INSURANCE_ID", Category.PHI,
   r"\b(?:INS|INSUR|POLICY)[_\-:#]?\s?[A-Z0-9]{6,15}\b",
   0.82, "HIPAA §164.514(b)(2)", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["insurance", "policy", "member", "subscriber", "plan", "coverage"])

_e("DATE_OF_SERVICE", Category.PHI,
   r"\b(?:DOS|date of service)[:\s]*(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b",
   0.90, "HIPAA §164.514(b)(2)", DefaultAction.GENERALIZE, RiskLevel.MEDIUM,
   flags=re.IGNORECASE,
   context_keywords=["service date", "encounter date", "visit date", "dos", "admission"])

_e("BLOOD_TYPE", Category.PHI,
   r"\b(?:A|B|AB|O)[+\-](?:\s|$|\b)",
   0.70, "HIPAA §164.514(b)", DefaultAction.GENERALIZE, RiskLevel.MEDIUM,
   format_strict=False,
   context_keywords=["blood", "type", "rh", "transfusion", "donor", "blood group"])

_e("GENETIC_MARKER", Category.PHI,
   r"\b(?:rs\d{4,10}|BRCA[12]|HLA-[A-Z0-9]+|CYP[0-9A-Z]+)\b",
   0.85, "HIPAA §164.514, GINA Title II", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["gene", "genetic", "snp", "mutation", "variant", "allele", "genomic"])

_e("LAB_RESULT", Category.PHI,
   r"\b(?:WBC|RBC|HGB|HCT|PLT|BUN|CRP|A1C|TSH|PSA|ALT|AST|GFR|LDL|HDL|BNP)[\s:=]+\d+\.?\d*\s*(?:mg/dL|g/dL|mL|mmol/L|U/L|%|ng/mL|mIU/L|cells/uL|x10\^?[0-9])?\b",
   0.91, "HIPAA §164.514(b)", DefaultAction.REDACT, RiskLevel.HIGH,
   flags=re.IGNORECASE,
   context_keywords=["lab", "result", "test", "value", "level", "count", "panel"])

# ─── PCI (8 types) ──────────────────────────────────────────────────────────

_e("CREDIT_CARD_PAN", Category.PCI,
   r"(?<!\d)(?:4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}|6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|(?:2131|1800|35\d{3})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)",
   0.95, "PCI DSS 4.0 Req.3.4", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["card", "credit", "debit", "pan", "payment", "visa", "mastercard", "amex"])

_e("CVV", Category.PCI,
   r"(?:cvv|cvc|cvv2|cvc2|cid|security\s*code)[:\s]+(\d{3,4})\b",
   0.94, "PCI DSS 4.0 Req.3.3.2", DefaultAction.REDACT, RiskLevel.CRITICAL,
   flags=re.IGNORECASE,
   context_keywords=["cvv", "cvc", "security code", "card verification"])

_e("CARD_EXPIRY", Category.PCI,
   r"\b(?:0[1-9]|1[0-2])[/\-](?:2[0-9]|3[0-9])\b",
   0.70, "PCI DSS 4.0 Req.3.4", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["expir", "exp", "valid thru", "valid through", "expiry", "expiration"])

_e("CARDHOLDER_NAME", Category.PCI,
   r"(?:cardholder|card\s*holder|name\s*on\s*card)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
   0.80, "PCI DSS 4.0 Req.3.4", DefaultAction.PSEUDONYMIZE, RiskLevel.HIGH,
   flags=re.IGNORECASE,
   context_keywords=["cardholder", "card holder", "name on card"])

_e("BANK_ACCOUNT", Category.PCI,
   r"(?<!\d)\d{8,17}(?!\d)",
   0.40, "PCI DSS 4.0 Req.3", DefaultAction.REDACT, RiskLevel.HIGH,
   format_strict=False,
   context_keywords=["account", "bank account", "acct", "checking", "savings", "deposit"])

_e("ROUTING_NUMBER", Category.PCI,
   r"\b(?:0[1-9]|[12]\d|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b",
   0.65, "PCI DSS 4.0 Req.3", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["routing", "aba", "transit", "rtn"])

_e("SWIFT_BIC", Category.PCI,
   r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
   0.70, "PCI DSS 4.0, GDPR Art.4(1)", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   format_strict=False,
   context_keywords=["swift", "bic", "bank code", "wire", "transfer"])

_e("IBAN", Category.PCI,
   r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,18})\b",
   0.92, "PCI DSS 4.0, EU PSD2", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["iban", "international bank", "account number", "wire"])

# ─── FINANCIAL (8 types) ────────────────────────────────────────────────────

_e("ACCOUNT_NO", Category.FINANCIAL,
   r"(?<!\d)\d{10,14}(?!\d)",
   0.35, "SOX §302, GDPR Art.4(1)", DefaultAction.REDACT, RiskLevel.HIGH,
   format_strict=False,
   context_keywords=["account", "acct", "account number", "deposit", "folio"])

_e("CUSIP", Category.FINANCIAL,
   r"\b[0-9]{3}[A-Z0-9]{3}[0-9]{2}[0-9]\b",
   0.75, "SOX §302, SEC Rule 17a-4", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   context_keywords=["cusip", "security", "bond", "equity", "fund"])

_e("ISIN", Category.FINANCIAL,
   r"\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b",
   0.80, "SOX §302, ISO 6166", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   context_keywords=["isin", "security", "instrument", "bond", "equity"])

_e("SEDOL", Category.FINANCIAL,
   r"\b[B-DF-HJ-NP-TV-Z0-9]{6}[0-9]\b",
   0.65, "SOX §302, LSE", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   format_strict=False,
   context_keywords=["sedol", "london", "stock", "exchange", "security"])

_e("TICKER_SYMBOL", Category.FINANCIAL,
   r"(?:ticker|symbol|stock)[:\s]+([A-Z]{1,5})\b",
   0.60, "SEC Rule 17a-4", DefaultAction.GENERALIZE, RiskLevel.LOW,
   context_keywords=["ticker", "symbol", "stock", "nyse", "nasdaq", "exchange"])

_e("TRADE_SECRET_MARKER", Category.FINANCIAL,
   r"\b(?:CONFIDENTIAL|TRADE[\s_]SECRET|PROPRIETARY|RESTRICTED|INTERNAL[\s_]ONLY|NOT[\s_]FOR[\s_]DISTRIBUTION)\b",
   0.93, "DTSA 18 U.S.C. §1836, EU Dir 2016/943", DefaultAction.REDACT, RiskLevel.CRITICAL,
   flags=re.IGNORECASE,
   context_keywords=["trade secret", "confidential", "classified", "proprietary"])

_e("SWIFT_BIC_FIN", Category.FINANCIAL,
   r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
   0.65, "ISO 9362, SWIFT Network", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   format_strict=False,
   context_keywords=["swift", "bic", "correspondent", "wire", "payment"])

_e("LEI", Category.FINANCIAL,
   r"\b[0-9A-Z]{4}00[A-Z0-9]{12}\d{2}\b",
   0.85, "ISO 17442, MiFID II Art.26", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   context_keywords=["lei", "legal entity", "identifier", "mifid"])

# ─── IP / CODE SECRETS (9 types) ────────────────────────────────────────────

_e("API_KEY", Category.IP_CODE,
   r"\b(?:sk-[A-Za-z0-9]{20,50}|sk-proj-[A-Za-z0-9\-]{40,}|rk_live_[A-Za-z0-9]{20,}|pk_live_[A-Za-z0-9]{20,})\b",
   0.98, "OWASP Top 10 A07:2021", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["api", "key", "secret", "token", "credential"])

_e("SECRET_TOKEN", Category.IP_CODE,
   r"(?:token|secret|password|api_key|apikey|auth|bearer)[=:\s\"\']+([A-Za-z0-9/+=_\-]{20,80})\b",
   0.90, "OWASP Top 10 A07:2021", DefaultAction.REDACT, RiskLevel.CRITICAL,
   flags=re.IGNORECASE,
   context_keywords=["token", "secret", "bearer", "auth", "credential"])

_e("PRIVATE_KEY", Category.IP_CODE,
   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
   0.99, "OWASP Top 10 A02:2021", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["private key", "pem", "certificate", "rsa", "ssh"])

_e("AWS_ACCESS_KEY", Category.IP_CODE,
   r"\bAKIA[A-Z0-9]{16}\b",
   0.99, "AWS Security Best Practices, CIS AWS 1.14", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["aws", "access key", "iam", "credential", "amazon"])

_e("GCP_SERVICE_KEY", Category.IP_CODE,
   r"\b[0-9]+-[a-z0-9]+@[a-z\-]+\.iam\.gserviceaccount\.com\b",
   0.97, "GCP Security Best Practices", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["gcp", "google", "service account", "iam", "gcloud"])

_e("GITHUB_TOKEN", Category.IP_CODE,
   r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
   0.99, "GitHub Security Advisories", DefaultAction.REDACT, RiskLevel.CRITICAL,
   context_keywords=["github", "token", "pat", "personal access", "gh"])

_e("JWT_TOKEN", Category.IP_CODE,
   r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
   0.97, "OWASP Top 10 A07:2021, RFC 7519", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["jwt", "token", "bearer", "authorization", "auth"])

_e("CONNECTION_STRING", Category.IP_CODE,
   r"(?:(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|mssql|redis|amqp)://[^\s\"']{10,200}|(?:Server|Data Source)=[^\s;]{5,};[^\s\"']{10,200})",
   0.96, "OWASP Top 10 A07:2021", DefaultAction.REDACT, RiskLevel.CRITICAL,
   flags=re.IGNORECASE,
   context_keywords=["connection", "database", "db", "dsn", "uri", "jdbc", "odbc"])

_e("PASSWORD_HASH", Category.IP_CODE,
   r"\$(?:2[aby]|5|6|argon2(?:id?)?|scrypt|pbkdf2)\$[^\s$]{8,}(?:\$[^\s$]{22,128}){1,2}",
   0.95, "NIST SP 800-63B", DefaultAction.REDACT, RiskLevel.HIGH,
   context_keywords=["password", "hash", "bcrypt", "argon", "scrypt"])

# ─── CUSTOM / ENTERPRISE (6 types) ──────────────────────────────────────────

_e("EMPLOYEE_ID", Category.CUSTOM,
   r"\b(?:EMP|EID|E)[_\-]?\d{5,10}\b",
   0.80, "GDPR Art.88, Internal HR Policy", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   context_keywords=["employee", "emp", "staff", "worker", "associate", "personnel"])

_e("CONTRACT_REF", Category.CUSTOM,
   r"\b(?:CON|CTR|CONTRACT)[_\-#]?[A-Z0-9]{4,12}\b",
   0.78, "Internal Legal Policy", DefaultAction.PSEUDONYMIZE, RiskLevel.MEDIUM,
   context_keywords=["contract", "agreement", "sow", "msa", "nda"])

_e("PROJECT_CODENAME", Category.CUSTOM,
   r"(?:project|codename|initiative)[:\s]+([A-Z][a-z]+(?:[_\-][A-Z][a-z]+){0,2})",
   0.55, "Internal IP Policy", DefaultAction.PSEUDONYMIZE, RiskLevel.LOW,
   flags=re.IGNORECASE,
   context_keywords=["project", "codename", "initiative", "operation"])

_e("INTERNAL_URL", Category.CUSTOM,
   r"\bhttps?://(?:[a-z0-9\-]+\.)*(?:internal|corp|intranet|private|local|staging|dev)\.[a-z0-9\-.]+(?:/[^\s]*)?\b",
   0.90, "Internal Security Policy", DefaultAction.REDACT, RiskLevel.HIGH,
   flags=re.IGNORECASE,
   context_keywords=["internal", "intranet", "corp", "private", "staging"])

_e("DOCUMENT_CLASSIFICATION", Category.CUSTOM,
   r"\b(?:TOP[\s_]SECRET|SECRET|CONFIDENTIAL|RESTRICTED|UNCLASSIFIED(?://FOUO)?|OFFICIAL[\s_]SENSITIVE|FOR[\s_]OFFICIAL[\s_]USE[\s_]ONLY)\b",
   0.94, "ISO 27001 A.8.2, EO 13526", DefaultAction.REDACT, RiskLevel.CRITICAL,
   flags=re.IGNORECASE,
   context_keywords=["classification", "marking", "handling", "caveat", "clearance"])

_e("DATA_SUBJECT_ID", Category.CUSTOM,
   r"\b(?:DSR|DSAR|SUBJ)[_\-#]?\d{5,12}\b",
   0.82, "GDPR Art.15-22", DefaultAction.PSEUDONYMIZE, RiskLevel.HIGH,
   context_keywords=["data subject", "dsar", "request", "right to", "erasure"])


# ── Context keywords registry ───────────────────────────────────────────────

_CONTEXT_KEYWORDS: dict[str, list[str]] = {
    d.entity_type: d.context_keywords for d in _ENTITY_DEFS
}


def get_context_keywords() -> dict[str, list[str]]:
    """Return context keywords for every entity type."""
    return dict(_CONTEXT_KEYWORDS)


# ── Stage 2: Context-aware confidence scoring ────────────────────────────────

_CONTEXT_WINDOW = 80  # chars before/after match to scan for keywords


def _compute_confidence(edef: _EntityDef, match: re.Match, text: str) -> float:
    """
    Dynamic confidence = base × context_multiplier × format_score, clamped [0, 1].
    """
    base = edef.base_confidence

    # Context multiplier: check for keywords near the match
    start = max(0, match.start() - _CONTEXT_WINDOW)
    end = min(len(text), match.end() + _CONTEXT_WINDOW)
    window = text[start:end].lower()

    context_multiplier = 1.0
    if edef.context_keywords:
        hits = sum(1 for kw in edef.context_keywords if kw.lower() in window)
        if hits >= 2:
            context_multiplier = 1.15
        elif hits == 1:
            context_multiplier = 1.08
        else:
            context_multiplier = 0.85

    # Negative context: words that suggest false positive
    negative_indicators = {
        "SSN": ["flight", "route", "order #", "invoice", "zip", "postal"],
        "PHONE": ["year", "zip", "postal code", "extension", "ext"],
        "PASSPORT_NO": ["flight", "model", "serial", "version", "ref"],
        "CREDIT_CARD_PAN": ["phone", "fax", "order", "tracking"],
        "BANK_ACCOUNT": ["phone", "zip", "year", "date", "time", "port"],
        "IP_ADDRESS": ["version", "v4", "v6"],
        "VIN": ["serial", "model"],
        "PROVIDER_NPI": ["zip", "phone", "fax", "year"],
        "DIAGNOSIS_CODE": ["version", "section", "chapter", "page"],
    }
    neg_keywords = negative_indicators.get(edef.entity_type, [])
    neg_hits = sum(1 for kw in neg_keywords if kw.lower() in window)
    if neg_hits:
        context_multiplier *= max(0.5, 1.0 - 0.15 * neg_hits)

    # Format strictness score
    format_score = 1.0 if edef.format_strict else 0.90

    confidence = base * context_multiplier * format_score
    return max(0.0, min(1.0, round(confidence, 4)))


# ── Stage 3: Luhn validation for credit cards ────────────────────────────────

def _post_validate(edef: _EntityDef, matched_text: str) -> bool:
    """Return False to reject a match after regex."""
    if edef.entity_type == "CREDIT_CARD_PAN":
        return validate_luhn(matched_text)
    if edef.entity_type == "IP_ADDRESS":
        parts = matched_text.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return True


# ── Stage 4: Overlap deduplication ───────────────────────────────────────────

def _deduplicate(hits: list[Detection]) -> list[Detection]:
    """Remove overlapping detections, preferring longer span + higher confidence."""
    hits.sort(key=lambda d: (-len(d.text), -d.confidence, d.start))
    accepted: list[Detection] = []
    taken: list[tuple[int, int]] = []

    for h in hits:
        overlaps = False
        for ts, te in taken:
            if h.start < te and h.end > ts:
                overlaps = True
                break
        if not overlaps:
            accepted.append(h)
            taken.append((h.start, h.end))

    accepted.sort(key=lambda d: d.start)
    return accepted


# ── Main scan function ───────────────────────────────────────────────────────

def scan_text(text: str) -> list[dict]:
    """
    Run the full 4-stage detection pipeline and return enriched entity dicts.

    Stage 1: Regex pattern matching (50+ entity types)
    Stage 2: Context-aware confidence scoring
    Stage 3: Post-validation (Luhn, IP range, etc.)
    Stage 4: Overlap deduplication
    """
    raw_hits: list[Detection] = []

    for edef in _ENTITY_DEFS:
        for m in edef.pattern.finditer(text):
            # Stage 3: post-validation
            if not _post_validate(edef, m.group()):
                continue

            # Stage 2: dynamic confidence
            confidence = _compute_confidence(edef, m, text)

            raw_hits.append(Detection(
                entity_type=edef.entity_type,
                text=m.group(),
                start=m.start(),
                end=m.end(),
                confidence=confidence,
                category=edef.category.value,
                regulatory_basis=edef.regulatory_basis,
                default_action=edef.default_action.value,
                risk_level=edef.risk_level.value,
            ))

    # Stage 4: dedup
    results = _deduplicate(raw_hits)

    return [
        {
            "entity_type": d.entity_type,
            "original_text": d.text,
            "start": d.start,
            "end": d.end,
            "confidence": d.confidence,
            "category": d.category,
            "regulatory_basis": d.regulatory_basis,
            "default_action": d.default_action,
            "risk_level": d.risk_level,
        }
        for d in results
    ]


# ── Backward-compatible API ──────────────────────────────────────────────────

def detect(text: str) -> list[Detection]:
    """Backward-compatible: scan text and return Detection objects."""
    raw_hits: list[Detection] = []

    for edef in _ENTITY_DEFS:
        for m in edef.pattern.finditer(text):
            if not _post_validate(edef, m.group()):
                continue
            confidence = _compute_confidence(edef, m, text)
            raw_hits.append(Detection(
                entity_type=edef.entity_type,
                text=m.group(),
                start=m.start(),
                end=m.end(),
                confidence=confidence,
                category=edef.category.value,
                regulatory_basis=edef.regulatory_basis,
                default_action=edef.default_action.value,
                risk_level=edef.risk_level.value,
            ))

    return _deduplicate(raw_hits)


# ── Registry & stats utilities ───────────────────────────────────────────────

def get_entity_registry() -> dict:
    """Return full registry of supported entity types with metadata."""
    registry = {}
    for edef in _ENTITY_DEFS:
        registry[edef.entity_type] = {
            "category": edef.category.value,
            "base_confidence": edef.base_confidence,
            "regulatory_basis": edef.regulatory_basis,
            "default_action": edef.default_action.value,
            "risk_level": edef.risk_level.value,
            "context_keywords": edef.context_keywords,
            "format_strict": edef.format_strict,
        }
    return registry


def get_detection_stats() -> dict:
    """Return counts of supported entity types by category."""
    stats: dict[str, int] = {}
    for edef in _ENTITY_DEFS:
        cat = edef.category.value
        stats[cat] = stats.get(cat, 0) + 1
    stats["TOTAL"] = len(_ENTITY_DEFS)
    return stats
