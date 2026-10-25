import urllib.request
import urllib.error
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from app.security import mask_pii, generate_consent_hash

BASE_URL = "http://127.0.0.1:8000"


def ensure_server_running():
    """Checks if FastAPI is running on port 8000; if not, starts it automatically."""
    try:
        urllib.request.urlopen(f"{BASE_URL}/api/assets", timeout=1)
        return None  # Server is already running in another terminal
    except Exception:
        print("[INFO] FastAPI server not detected on port 8000. Starting background server...")
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait up to 10 seconds for server startup
        for _ in range(20):
            time.sleep(0.5)
            try:
                urllib.request.urlopen(f"{BASE_URL}/api/assets", timeout=1)
                print("[INFO] Background FastAPI server is up and ready!\n")
                return proc
            except Exception:
                continue
        proc.terminate()
        raise RuntimeError("Failed to start background FastAPI server.")


def run_unit_tests():
    print("=== 1. RUNNING SECURITY & MASKING UNIT TESTS ===")

    masked_pan = mask_pii("ABCDE1234F", "PAN")
    assert masked_pan == "XXXXXX234F", f"PAN Masking Failed: {masked_pan}"
    print(f"[PASS] PAN Masking: ABCDE1234F -> {masked_pan}")

    masked_phone = mask_pii("9876543210", "Phone")
    assert masked_phone == "+91-XXXXXX3210", f"Phone Masking Failed: {masked_phone}"
    print(f"[PASS] Phone Masking: 9876543210 -> {masked_phone}")

    masked_email = mask_pii("student@btech.edu.in", "Email")
    assert masked_email == "s*****t@btech.edu.in", f"Email Masking Failed: {masked_email}"
    print(f"[PASS] Email Masking: student@btech.edu.in -> {masked_email}")

    ts = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    h1 = generate_consent_hash("Test User", masked_pan, "KYC", "Active", ts)
    h2 = generate_consent_hash("Test User", masked_pan, "KYC", "Revoked", ts)
    assert h1 != h2 and len(h1) == 64, "SHA-256 Hash generation failed"
    print("[PASS] SHA-256 Ledger Integrity Verified (Active != Revoked)")


def run_api_integration_tests():
    print("\n=== 2. RUNNING LIVE API INTEGRATION TESTS ===")

    # 1. Create a Consent Record via POST /api/consent
    consent_payload = json.dumps({
        "principal_name": "Automated Test User",
        "pii_type": "PAN",
        "raw_identifier": "ZYXWV9876K",
        "purpose": "Automated Security Audit"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}/api/consent",
        data=consent_payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as response:
        assert response.status == 201
        data = json.loads(response.read().decode())
        consent_id = data["id"]
        assert data["principal_id_masked"] == "XXXXXX876K"
        print(f"[PASS] POST /api/consent (ID #{consent_id} created with masked PAN: {data['principal_id_masked']})")

    # 2. Revoke the Consent via POST /api/consent/{id}/revoke
    revoke_req = urllib.request.Request(
        f"{BASE_URL}/api/consent/{consent_id}/revoke",
        method="POST"
    )
    with urllib.request.urlopen(revoke_req) as response:
        assert response.status == 200
        revoked_data = json.loads(response.read().decode())
        assert revoked_data["status"] == "Revoked"
        assert revoked_data["consent_hash"] != data["consent_hash"]
        print(f"[PASS] POST /api/consent/{consent_id}/revoke (Status updated to Revoked & New Hash Sealed)")

    # 3. Verify Statutory Breach Report Generation
    with urllib.request.urlopen(f"{BASE_URL}/api/incidents/1/report") as response:
        assert response.status == 200
        report = json.loads(response.read().decode())
        assert "STATUTORY PERSONAL DATA BREACH NOTIFICATION" in report["report_markdown"]
        print("[PASS] GET /api/incidents/1/report (Statutory Markdown Dossier Verified)")

    print("\nALL DPDP ACT COMPLIANCE TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_unit_tests()
    server_proc = ensure_server_running()
    try:
        run_api_integration_tests()
    finally:
        if server_proc:
            server_proc.terminate()