from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime, timezone
from .database import Base

class DataAsset(Base):
    __tablename__ = "data_assets"

    id = Column(Integer, primary_key=True, index=True)
    asset_name = Column(String, index=True, nullable=False)
    department = Column(String, nullable=False)
    pii_type = Column(String, nullable=False)        # e.g., Aadhaar, PAN, Phone, Email, Financial
    storage_location = Column(String, nullable=False) # e.g., AWS Mumbai (ap-south-1), On-Prem Server
    lawful_basis = Column(String, nullable=False)    # e.g., Explicit Consent (Sec 6), Legitimate Use (Sec 7)
    retention_years = Column(Integer, nullable=False)
    security_safeguards = Column(String, nullable=False) # e.g., AES-256, RBAC, TLS 1.3
    is_encrypted = Column(Boolean, default=True)


class ConsentRecord(Base):
    __tablename__ = "consent_records"

    id = Column(Integer, primary_key=True, index=True)
    principal_name = Column(String, index=True, nullable=False)
    pii_type = Column(String, nullable=False)
    principal_id_masked = Column(String, nullable=False)
    purpose = Column(String, nullable=False)
    status = Column(String, default="Active", nullable=False) # "Active" or "Revoked"
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    consent_hash = Column(String, unique=True, index=True, nullable=False)


class BreachIncident(Base):
    __tablename__ = "breach_incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_title = Column(String, nullable=False)
    affected_systems = Column(String, nullable=False)
    severity = Column(String, nullable=False) # Low, Medium, High, Critical
    affected_records = Column(Integer, nullable=False)
    detected_at = Column(DateTime, nullable=False)
    cert_in_deadline = Column(DateTime, nullable=False)
    dpb_deadline = Column(DateTime, nullable=False)
    status = Column(String, default="Investigating", nullable=False)