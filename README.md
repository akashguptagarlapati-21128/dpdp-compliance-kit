# 🛡️ DPDP Act 2023 Compliance Automation Kit (Indian SME Edition)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-SQLAlchemy_ORM-003B57?logo=sqlite&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Frontend-Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white)
![Compliance](https://img.shields.io/badge/Regulation-DPDP_Act_2023_%26_CERT--In-emerald)

A lightweight, self-contained **Privacy Engineering & Regulatory Compliance Automation Platform** built specifically for Indian Micro, Small, and Medium Enterprises (MSMEs/SMEs). This toolkit operationalizes the core technical mandates of India's **Digital Personal Data Protection Act, 2023 (DPDP Act)** and **CERT-In Cybersecurity Directions (Section 70B of the IT Act, 2000)**.

---

## 🎯 Problem Statement

Under the **DPDP Act 2023**, Indian businesses acting as *Data Fiduciaries* face strict statutory obligations regarding personal data inventory, explicit itemized consent, data minimization, and rapid breach reporting (with penalties reaching up to ₹250 Crore for non-compliance). While large enterprises deploy expensive GRC suites, Indian SMEs lack an accessible, zero-configuration system to track data assets, prove consent cryptographically, and manage dual breach reporting deadlines (**6 hours for CERT-In** and **72 hours for the Data Protection Board of India**).

---

## ✨ Key Functional & Security Features

### 1. Data Mapping & Record of Processing Activities (DPDP Sec 5, 7 & 8)
* **Centralized Asset Inventory:** Tracks internal repositories (CRMs, Payroll DBs, Cloud Buckets) storing Digital Personal Data.
* **Lawful Basis & Retention Tagging:** Maps each asset to its statutory lawful basis (*Explicit Consent under Sec 6* or *Certain Legitimate Uses under Sec 7*) and enforces retention visibility.
* **Automated Posture Risk Flagging:** Automatically highlights unencrypted data stores with an `UNENCRYPTED RISK` alert badge to enforce **Section 8(5)** reasonable security safeguards.

### 2. Consent Manager, Dynamic PII Masking & SHA-256 Ledger (DPDP Sec 6)
* **In-Memory Dynamic PII Masking:** Raw Indian identifiers are masked via regular expressions *before* database persistence—raw PII is never written to disk:
  * **PAN:** `ABCDE1234F` $\rightarrow$ `XXXXXX234F`
  * **Aadhaar:** `1234-5678-9012` $\rightarrow$ `XXXX-XXXX-9012`
  * **Phone:** `9876543210` $\rightarrow$ `+91-XXXXXX3210`
  * **Email:** `user@domain.in` $\rightarrow$ `u**r@domain.in`
* **Tamper-Evident SHA-256 Audit Ledger:** Every consent grant or withdrawal generates a deterministic 64-character cryptographic SHA-256 digest (`DPDP2023|principal|masked_id|purpose|status|iso_timestamp`).
* **One-Click Consent Withdrawal (Sec 6(4)):** Allows instant opt-out, updating the ledger state to `Revoked` and re-sealing the record with a new timestamped cryptographic hash.

### 3. Breach Notification & Dual SLA Countdown Tracker (DPDP Sec 8(6) & CERT-In)
* **Real-Time Dual SLA Clocks:** Automatically calculates and renders live 1-second countdown timers upon incident declaration:
  * **CERT-In 6-Hour Mandate:** Pursuant to CERT-In Directions under Section 70B(6) of the IT Act, 2000.
  * **Data Protection Board of India (DPBI) 72-Hour Mandate:** Pursuant to Section 8(6) of the DPDP Act, 2023.
* **Automated Statutory Dossier Generator:** Generates a downloadable and copyable Markdown (`.md`) regulatory filing pre-populated with incident metadata, affected Data Principals, forensic preservation checklists, and Eighth Schedule language notification plans.

---

## 🏗️ System Architecture & Directory Structure

```text
dpdp-compliance-kit/
├── requirements.txt          # Python package dependencies
├── test_compliance.py        # Automated unit & live API integration test suite
├── dpdp_compliance.db        # Auto-generated SQLite relational database
├── app/
│   ├── __init__.py           # Package initializer
│   ├── database.py           # SQLAlchemy engine & session dependency management
│   ├── models.py             # ORM models (DataAsset, ConsentRecord, BreachIncident)
│   ├── schemas.py            # Pydantic v2 schemas for strict input/output validation
│   ├── security.py           # Regex PII masking engine & SHA-256 checksum generator
│   └── main.py               # FastAPI REST controllers, DB seeding & static mounting
└── static/
    └── index.html            # Responsive Single-Page Application (Tailwind CSS + Vanilla JS)
```

---

## 🚀 Quick Start & Installation Guide

### Prerequisites
* **Python 3.10+** installed on Windows, macOS, or Linux.
* **VS Code** (or any terminal environment).

### 1. Clone or Open the Project Folder
```powershell
cd dpdp-compliance-kit
```

### 2. Create and Activate a Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate on Windows (PowerShell):
venv\Scripts\activate

# Activate on macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install --only-binary=:all: -r requirements.txt
```

### 4. Start the FastAPI Server
```powershell
python -m uvicorn app.main:app --reload --port 8000
```

### 5. Access the Application
* **Live Compliance Dashboard:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Interactive Swagger API Docs (OpenAPI):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧪 Running Automated Security & API Tests

The project includes a zero-dependency automated verification suite (`test_compliance.py`) that validates the PII masking logic, SHA-256 hash determinism, and live REST API endpoints:

```powershell
python test_compliance.py
```

**Expected Output:**
```text
=== 1. RUNNING SECURITY & MASKING UNIT TESTS ===
[PASS] PAN Masking: ABCDE1234F -> XXXXXX234F
[PASS] Phone Masking: 9876543210 -> +91-XXXXXX3210
[PASS] Email Masking: student@btech.edu.in -> s*****t@btech.edu.in
[PASS] SHA-256 Ledger Integrity Verified (Active != Revoked)

=== 2. RUNNING LIVE API INTEGRATION TESTS ===
[PASS] POST /api/consent (ID #3 created with masked PAN: XXXXXX876K)
[PASS] POST /api/consent/3/revoke (Status updated to Revoked & New Hash Sealed)
[PASS] GET /api/incidents/1/report (Statutory Markdown Dossier Verified)

ALL DPDP ACT COMPLIANCE TESTS PASSED SUCCESSFULLY!
```

---

## 🔌 REST API Reference

| Method | Endpoint | Description | DPDP / Regulatory Mapping |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/assets` | List all mapped personal data assets | Sec 8(4) & Sec 8(5) |
| `POST` | `/api/assets` | Register a new internal data asset & safeguards | Sec 5, Sec 7 & Sec 8(5) |
| `GET` | `/api/consent` | Retrieve the cryptographic consent audit ledger | Sec 6(1) & Sec 6(10) |
| `POST` | `/api/consent` | Mask raw PII & record consent with SHA-256 hash | Sec 6(1) & Data Minimization |
| `POST` | `/api/consent/{id}/revoke` | Withdraw consent & compute new revocation hash | Sec 6(4) & Sec 6(6) |
| `GET` | `/api/incidents` | List all security breaches & SLA deadlines | Sec 8(6) & CERT-In |
| `POST` | `/api/incidents` | Declare a breach & trigger 6h/72h SLA timers | Sec 8(6) & IT Act Sec 70B |
| `GET` | `/api/incidents/{id}/report` | Auto-generate statutory Markdown breach notice | Sec 8(6) & CERT-In Mandate |

---


## 📄 License
Developed for academic and cybersecurity compliance demonstration purposes under the **MIT License**.