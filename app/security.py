import hashlib
import re
from datetime import datetime

def mask_pii(value: str, pii_type: str) -> str:
    """
    Dynamically masks sensitive Indian Personal Data identifiers before storage.
    Raw PII is never written to disk in the Consent Ledger.
    """
    if not value:
        return "REDACTED"
    
    val = value.strip()
    ptype = pii_type.upper().strip()

    if ptype == "PAN":
        clean_val = re.sub(r"[^a-zA-Z0-9]", "", val).upper()
        if len(clean_val) == 10:
            return f"XXXXXX{clean_val[6:]}"
        return "X" * max(0, len(val) - 4) + val[-4:]

    elif ptype == "AADHAAR":
        digits = re.sub(r"\D", "", val)
        if len(digits) == 12:
            return f"XXXX-XXXX-{digits[-4:]}"
        return "XXXX-XXXX-" + val[-4:]

    elif ptype == "PHONE":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 10:
            return f"+91-XXXXXX{digits[-4:]}"
        return "XXXXXX" + val[-4:]

    elif ptype == "EMAIL":
        if "@" in val:
            local, domain = val.split("@", 1)
            if len(local) > 2:
                return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
            return f"*@{domain}"
        return "REDACTED_EMAIL"

    elif ptype == "FINANCIAL":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 4:
            return f"XXXX-XXXX-{digits[-4:]}"
        return "XXXX-FINANCIAL"

    else:
        if len(val) > 4:
            return "X" * (len(val) - 4) + val[-4:]
        return "XXXX"


def generate_consent_hash(
    principal_name: str,
    principal_id_masked: str,
    purpose: str,
    status: str,
    timestamp: datetime
) -> str:
    """
    Generates an immutable, deterministic SHA-256 cryptographic checksum 
    representing the exact state of a Data Principal's consent artifact.
    """
    iso_time = timestamp.isoformat()
    payload = f"DPDP2023|{principal_name.strip().lower()}|{principal_id_masked}|{purpose.strip()}|{status.upper()}|{iso_time}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()