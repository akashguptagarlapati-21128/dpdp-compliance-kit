from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional

class DataAssetBase(BaseModel):
    asset_name: str = Field(..., example="Customer CRM Database")
    department: str = Field(..., example="Sales & Marketing")
    pii_type: str = Field(..., example="PAN, Phone, Email")
    storage_location: str = Field(..., example="AWS Region ap-south-1 (Mumbai)")
    lawful_basis: str = Field(..., example="Consent (Sec 6)")
    retention_years: int = Field(..., ge=1, le=50, example=5)
    security_safeguards: str = Field(..., example="AES-256 at rest, RBAC")
    is_encrypted: bool = Field(default=True)

class DataAssetCreate(DataAssetBase):
    pass

class DataAssetResponse(DataAssetBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


class ConsentCreate(BaseModel):
    principal_name: str = Field(..., example="Aarav Sharma")
    pii_type: str = Field(..., example="PAN")
    raw_identifier: str = Field(..., description="Raw PII value; masked immediately and never stored in plaintext", example="ABCDE1234F")
    purpose: str = Field(..., example="KYC Verification for Onboarding")

class ConsentResponse(BaseModel):
    id: int
    principal_name: str
    pii_type: str
    principal_id_masked: str
    purpose: str
    status: str
    timestamp: datetime
    consent_hash: str
    model_config = ConfigDict(from_attributes=True)


class BreachIncidentCreate(BaseModel):
    incident_title: str = Field(..., example="Unauthorized API Access on Billing Portal")
    affected_systems: str = Field(..., example="Billing Microservice, PostgreSQL Replica")
    severity: str = Field(..., example="Critical")
    affected_records: int = Field(..., ge=1, example=14500)
    detected_at: Optional[datetime] = None

class BreachIncidentResponse(BaseModel):
    id: int
    incident_title: str
    affected_systems: str
    severity: str
    affected_records: int
    detected_at: datetime
    cert_in_deadline: datetime
    dpb_deadline: datetime
    status: str
    model_config = ConfigDict(from_attributes=True)

class IncidentReportResponse(BaseModel):
    incident_id: int
    generated_at: datetime
    report_markdown: str