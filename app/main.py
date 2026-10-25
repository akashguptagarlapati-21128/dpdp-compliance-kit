from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing import List
import os

from . import models, schemas, security
from .database import engine, SessionLocal, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="DPDP Act 2023 Compliance Automation Kit",
    description="Self-contained compliance engine for Indian SMEs covering Data Mapping (Sec 8), Consent & Masking (Sec 6), and Breach SLA Tracking (Sec 8(6) & CERT-In).",
    version="1.0.0",
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def seed_initial_data():
    """Seeds realistic Indian SME compliance records on first run so the dashboard is immediately alive."""
    db = SessionLocal()
    try:
        if db.query(models.DataAsset).count() == 0:
            sample_assets = [
                models.DataAsset(
                    asset_name="Zoho CRM Customer Master",
                    department="Sales & Onboarding",
                    pii_type="PAN, Phone, Email",
                    storage_location="AWS Mumbai Region (ap-south-1)",
                    lawful_basis="Explicit Consent (Sec 6)",
                    retention_years=5,
                    security_safeguards="AES-256 Encryption, Role-Based Access Control (RBAC)",
                    is_encrypted=True,
                ),
                models.DataAsset(
                    asset_name="HRMS & Payroll Ledger",
                    department="Human Resources",
                    pii_type="Aadhaar, PAN, Financial",
                    storage_location="On-Premises Vault (Bengaluru HQ)",
                    lawful_basis="Certain Legitimate Uses - Employment (Sec 7(i))",
                    retention_years=8,
                    security_safeguards="Disk Encryption (BitLocker), MFA, Audit Logging",
                    is_encrypted=True,
                ),
                models.DataAsset(
                    asset_name="Legacy Support Ticketing Dump",
                    department="Customer Support",
                    pii_type="Phone, Email",
                    storage_location="Local NAS Server",
                    lawful_basis="Explicit Consent (Sec 6)",
                    retention_years=2,
                    security_safeguards="VLAN Segmentation (Unencrypted CSVs)",
                    is_encrypted=False,
                ),
            ]
            db.add_all(sample_assets)

        if db.query(models.ConsentRecord).count() == 0:
            now = datetime.now(timezone.utc)
            c1_masked = security.mask_pii("ABCDE1234F", "PAN")
            c1_hash = security.generate_consent_hash("Rohan Deshmukh", c1_masked, "MSME Credit Line KYC Assessment", "Active", now)
            
            c2_time = now - timedelta(days=2)
            c2_masked = security.mask_pii("4567-8901-2345", "Aadhaar")
            c2_hash = security.generate_consent_hash("Priya Nair", c2_masked, "Biometric e-KYC Verification", "Revoked", c2_time)

            db.add_all([
                models.ConsentRecord(
                    principal_name="Rohan Deshmukh",
                    pii_type="PAN",
                    principal_id_masked=c1_masked,
                    purpose="MSME Credit Line KYC Assessment",
                    status="Active",
                    timestamp=now,
                    consent_hash=c1_hash,
                ),
                models.ConsentRecord(
                    principal_name="Priya Nair",
                    pii_type="Aadhaar",
                    principal_id_masked=c2_masked,
                    purpose="Biometric e-KYC Verification",
                    status="Revoked",
                    timestamp=c2_time,
                    consent_hash=c2_hash,
                ),
            ])

        if db.query(models.BreachIncident).count() == 0:
            # Detected 1 hour and 15 minutes ago so the live countdown timer shows ~4h 45m left for CERT-In
            detected = datetime.now(timezone.utc) - timedelta(hours=1, minutes=15)
            incident = models.BreachIncident(
                incident_title="Misconfigured S3 Bucket Exposing KYC Invoices",
                affected_systems="AWS S3 Bucket (prod-sme-invoices-mum), Billing Portal API",
                severity="Critical",
                affected_records=4250,
                detected_at=detected,
                cert_in_deadline=detected + timedelta(hours=6),
                dpb_deadline=detected + timedelta(hours=72),
                status="Containment in Progress",
            )
            db.add(incident)

        db.commit()
    finally:
        db.close()

seed_initial_data()


@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serves the main Single-Page Application dashboard."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))




@app.get("/api/assets", response_model=List[schemas.DataAssetResponse])
def list_data_assets(db: Session = Depends(get_db)):
    return db.query(models.DataAsset).order_by(models.DataAsset.id.desc()).all()


@app.post("/api/assets", response_model=schemas.DataAssetResponse, status_code=status.HTTP_201_CREATED)
def create_data_asset(asset: schemas.DataAssetCreate, db: Session = Depends(get_db)):
    db_asset = models.DataAsset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset




@app.get("/api/consent", response_model=List[schemas.ConsentResponse])
def list_consents(db: Session = Depends(get_db)):
    return db.query(models.ConsentRecord).order_by(models.ConsentRecord.timestamp.desc()).all()


@app.post("/api/consent", response_model=schemas.ConsentResponse, status_code=status.HTTP_201_CREATED)
def grant_consent(payload: schemas.ConsentCreate, db: Session = Depends(get_db)):
    masked_id = security.mask_pii(payload.raw_identifier, payload.pii_type)
    now = datetime.now(timezone.utc)
    
    c_hash = security.generate_consent_hash(
        principal_name=payload.principal_name,
        principal_id_masked=masked_id,
        purpose=payload.purpose,
        status="Active",
        timestamp=now,
    )

    record = models.ConsentRecord(
        principal_name=payload.principal_name,
        pii_type=payload.pii_type,
        principal_id_masked=masked_id,
        purpose=payload.purpose,
        status="Active",
        timestamp=now,
        consent_hash=c_hash,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@app.post("/api/consent/{consent_id}/revoke", response_model=schemas.ConsentResponse)
def revoke_consent(consent_id: int, db: Session = Depends(get_db)):
    record = db.query(models.ConsentRecord).filter(models.ConsentRecord.id == consent_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Consent record not found")
    
    if record.status == "Revoked":
        raise HTTPException(status_code=400, detail="Consent is already revoked")

    now = datetime.now(timezone.utc)
    record.status = "Revoked"
    record.timestamp = now
    record.consent_hash = security.generate_consent_hash(
        principal_name=record.principal_name,
        principal_id_masked=record.principal_id_masked,
        purpose=record.purpose,
        status="Revoked",
        timestamp=now,
    )
    db.commit()
    db.refresh(record)
    return record




@app.get("/api/incidents", response_model=List[schemas.BreachIncidentResponse])
def list_incidents(db: Session = Depends(get_db)):
    return db.query(models.BreachIncident).order_by(models.BreachIncident.detected_at.desc()).all()


@app.post("/api/incidents", response_model=schemas.BreachIncidentResponse, status_code=status.HTTP_201_CREATED)
def log_breach_incident(payload: schemas.BreachIncidentCreate, db: Session = Depends(get_db)):
    detected_time = payload.detected_at or datetime.now(timezone.utc)
    if detected_time.tzinfo is None:
        detected_time = detected_time.replace(tzinfo=timezone.utc)

    cert_in_sla = detected_time + timedelta(hours=6)
    dpbi_sla = detected_time + timedelta(hours=72)

    incident = models.BreachIncident(
        incident_title=payload.incident_title,
        affected_systems=payload.affected_systems,
        severity=payload.severity,
        affected_records=payload.affected_records,
        detected_at=detected_time,
        cert_in_deadline=cert_in_sla,
        dpb_deadline=dpbi_sla,
        status="Active Investigation",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@app.get("/api/incidents/{incident_id}/report", response_model=schemas.IncidentReportResponse)
def generate_statutory_report(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(models.BreachIncident).filter(models.BreachIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    det_iso = inc.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    cert_iso = inc.cert_in_deadline.strftime("%Y-%m-%d %H:%M:%S UTC")
    dpb_iso = inc.dpb_deadline.strftime("%Y-%m-%d %H:%M:%S UTC")

    report_md = f"""# STATUTORY PERSONAL DATA BREACH NOTIFICATION
**Regulatory Frameworks:** 
1. Section 8(6) of the Digital Personal Data Protection Act, 2023 (DPDP Act)
2. CERT-In Directions under Section 70B(6) of the Information Technology Act, 2000

---

## 1. FILING METADATA & SLA TIMELINES
* **Incident Reference ID:** `DPDP-INC-{inc.id:04d}`
* **Report Generated Timestamp:** {now.strftime("%Y-%m-%d %H:%M:%S UTC")}
* **Current Incident Status:** {inc.status}
* **Time of Breach Detection:** {det_iso}
* **CERT-In 6-Hour Statutory Deadline:** {cert_iso}
* **Data Protection Board of India (DPBI) 72-Hour Deadline:** {dpb_iso}

## 2. INCIDENT SUMMARY & SCOPE
* **Incident Title:** {inc.incident_title}
* **Assessed Severity Level:** {inc.severity.upper()}
* **Affected Information Systems / Assets:** {inc.affected_systems}
* **Estimated Number of Affected Data Principals:** {inc.affected_records:,} individuals

## 3. NATURE & IMPACT OF PERSONAL DATA BREACH (DPDP Sec 8(6))
* **Categories of Personal Data Involved:** Digital Personal Data processed by the Data Fiduciary within the affected systems ({inc.affected_systems}).
* **Likely Consequences for Data Principals:** Potential unauthorized access, disclosure, or misuse of personal identifiers requiring immediate credential rotation and vigilance against targeted phishing/social engineering.

## 4. MITIGATION & REMEDIAL MEASURES IMPLEMENTED
* **Immediate Containment:** Isolated affected host segments, revoked compromised IAM/API session tokens, and enabled strict ingress filtering.
* **Forensic Preservation:** System memory dumps, immutable audit logs, and network flow captures preserved in accordance with CERT-In log retention mandates (180-day baseline).
* **Data Principal Notification Plan:** Automated dispatch of plain-language breach notices (in English and Eighth Schedule languages under Sec 5(3)) instructing affected Data Principals on safety measures and providing direct contact details for the Consent Manager / Data Protection Officer.

## 5. DECLARATION BY DATA FIDUCIARY / DPO
I hereby declare that the information furnished above is true and accurate to the best of our forensic knowledge at this stage of the investigation.

* **Authorized Signatory:** Data Protection Officer (DPO) / Chief Information Security Officer (CISO)
* **Contact Email:** dpo-compliance@sme-enterprise.in
* **Submission Channels:** `incident@cert-in.org.in` (CERT-In) | DPBI Digital Portal
"""

    return schemas.IncidentReportResponse(
        incident_id=inc.id,
        generated_at=now,
        report_markdown=report_md,
    )