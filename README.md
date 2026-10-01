# Wooplix Zoho System Audit Agent

**Automated Diagnostic Engine & Deliverable Generator for Zoho Cloud Environments**  
*Built for **Wooplix Technologies Private Limited** (Authorized Zoho Partner)*

---

## Overview

The **Zoho System Audit Agent** is a full-stack, enterprise-grade diagnostic platform that inspects a client's Zoho environment, collects configuration and operational telemetry (CRM, Desk, Books, and Cross-App Integrations), analyzes vulnerabilities and misconfigurations using Groq LLM under strict **Wooplix House Style**, and generates authoritative, branded deliverables (**PDF** via Dompdf and **DOCX** via `python-docx`).

---

## Key Features

1. **OAuth Token Management & Environment Telemetry**:
   - Authenticates against Zoho Data Centers (`accounts.zoho.in`, `accounts.zoho.com`, `accounts.zoho.eu`, `accounts.zoho.com.au`).
   - Read-only telemetry collectors for:
     - **Zoho CRM**: Org settings, installed modules, custom fields, pipeline stages, lead assignment rules, dormant deal analysis, uncontacted leads, and permission governance.
     - **Zoho Desk**: Departments, active queues, response/resolution SLA policies, and supervisory escalation triggers.
     - **Zoho Books / Billing**: Currency setup, foreign exchange automation, overdue receivables, and invoice workflows.
     - **Cross-App Sync**: Data synchronization health, entity mapping gaps, and webhook status between CRM, Desk, and Books.
   - Built-in enriched baseline simulation mode for instant evaluations and testing without live production tokens.

2. **Groq LLM Diagnostic Analyzer**:
   - Leverages `openai/gpt-oss-120b` (with automated fallback to `llama-3.3-70b-versatile`, `openai/gpt-oss-20b`, `qwen/qwen3.8-27b`).
   - Runs with strict temperature (`0.1`) and structured JSON mode.
   - Strictly enforces **Wooplix House Style**: concrete, technical, and objective without marketing fluff or forbidden buzzwords (`seamless`, `cutting-edge`, `robust`, `holistic`, `synergy`, `delve`, `leverage`).

3. **Branded Deliverable Exporters**:
   - **DOCX Exporter**: Clean Microsoft Word documents styled with Wooplix brand colors (`#1a365d` Navy, `#008080` Teal, `#f8fafc` background), dual logos header, metadata table, severity badges, and phased roadmap.
   - **PDF Exporter**: High-resolution vector PDF rendered via local Dompdf (PHP) with embedded base64 headers and footers.
   - **All-in-One ZIP Package**: Bundles PDF, DOCX, and raw telemetry JSON.

4. **FastAPI Web Service & Intake Portal**:
   - High-performance asynchronous API (`app.py`).
   - Polished responsive UI (`index.html`) with dual branding, target suite selectors, password reveal toggles, execution pipeline stepper, and live deliverable download.

---

## Project Structure

```
├── zoho_audit_agent.py      # Core diagnostic engine, telemetry collectors, Groq LLM, & exporters
├── app.py                   # FastAPI web service & streaming download endpoints
├── index.html               # Modern branded intake portal
├── html_to_pdf.php          # Dompdf PHP bridge for pixel-perfect PDF rendering
├── composer.json            # PHP composer dependencies (dompdf/dompdf)
├── vendor/                  # Installed Dompdf PHP library
├── requirements.txt         # Python package dependencies
├── run.sh                   # One-click startup script
├── .env                     # Configuration (GROQ_API_KEY, Zoho credentials)
├── wooplix_main_logo.png    # Wooplix wordmark logo
├── wooplix_partner_badge.png# Zoho Authorized Partner badge
├── wooplix_logo.png         # Legacy partner badge
└── out/                     # Default output directory for generated deliverables
```

---

## Getting Started

### 1. Environment Configuration

Ensure your `.env` contains your active Groq API key:
```ini
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
ZOHO_ACCOUNTS_URL=https://accounts.zoho.in
```

### 2. Launch the Web Application

Run the startup script:
```bash
./run.sh
```
Or run directly with python:
```bash
python3 app.py
```
Open your browser at **`http://localhost:8000`**.

---

## Standalone CLI Usage

You can also run audits directly from the command line:

```bash
# Run audit using pre-configured sample/enriched baseline
python3 zoho_audit_agent.py --client "Acme Global Solutions" --auditor "Lead Systems Architect" --sample

# Run audit against live Zoho environment (using .env credentials)
python3 zoho_audit_agent.py --client "Nexus Logistics Ltd" --auditor "Ankita Pandey"
```

Generated outputs will be saved in `./out/`:
- `Wooplix_Audit_<Client>.pdf`
- `Wooplix_Audit_<Client>.docx`
- `Wooplix_Audit_<Client>.json`

---

## API Reference

### Health Check
```http
GET /api/health
```
Response:
```json
{
  "status": "healthy",
  "groq_configured": true,
  "zoho_env_configured": true,
  "model": "openai/gpt-oss-120b",
  "version": "2.0.0"
}
```

### Generate Audit Deliverables
```http
POST /api/audit?format=pdf
Content-Type: multipart/form-data
```
**Form Parameters**:
- `company_name` *(string)*: Client organization name.
- `auditor_name` *(string)*: Lead auditor name.
- `contact_email` *(string, optional)*: Client notification email.
- `accounts_url` *(string)*: Zoho accounts URL (e.g. `https://accounts.zoho.in`).
- `client_id` *(string, optional)*: Zoho OAuth Client ID.
- `client_secret` *(string, optional)*: Zoho OAuth Client Secret.
- `refresh_token` *(string, optional)*: Zoho OAuth Refresh Token.
- `target_suites` *(string)*: Comma-separated list (`zoho_crm,zoho_desk,zoho_books`).
- `use_demo` *(boolean, optional)*: If `true`, runs simulation telemetry.

**Format options**: `?format=pdf`, `?format=docx`, or `?format=zip`.
