#!/usr/bin/env python3
"""FastAPI Application for Wooplix Zoho System Audit Agent.

Serves the intake portal and provides API endpoints to trigger automated
Zoho diagnostic telemetry collection, LLM analysis via Groq, and deliverable export.
"""

import io
import os
import re
import json
import base64
import zipfile
import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Request, HTTPException, Form, Query
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

import zoho_audit_agent as agent

HERE = Path(__file__).resolve().parent

app = FastAPI(
    title="Wooplix Zoho System Audit Agent",
    description="Automated diagnostic engine and audit deliverable generator for Zoho cloud suites.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "Content-Disposition", "X-Audit-Client", "X-Audit-Filename",
        "X-Audit-Score", "X-Audit-Type", "X-Audit-Mode", "X-Audit-Telemetry"
    ]
)


@app.middleware("http")
async def vercel_path_rewrite(request: Request, call_next):
    """Normalize Vercel rewrite paths so FastAPI router receives the intended endpoint."""
    route = request.query_params.get("_route")
    if route:
        clean_route = "/" + route.lstrip("/")
        if not clean_route.startswith("/api"):
            clean_route = "/api" + clean_route
        request.scope["path"] = clean_route
    elif request.headers.get("x-matched-path"):
        matched = request.headers.get("x-matched-path")
        if matched and matched != "/api/index.py":
            request.scope["path"] = matched
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def serve_portal():
    candidates = [
        HERE / "public" / "index.html",
        HERE / "index.html",
        HERE.parent / "public" / "index.html",
        HERE.parent / "index.html",
        Path("public/index.html"),
        Path("index.html"),
    ]
    for c in candidates:
        if c.exists():
            return HTMLResponse(content=c.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Wooplix Zoho System Audit Agent</h1>")


@app.get("/wooplix_main_logo.png")
async def get_main_logo():
    for c in [HERE / "public" / "wooplix_main_logo.png", HERE / "wooplix_main_logo.png", HERE.parent / "wooplix_main_logo.png"]:
        if c.exists():
            return FileResponse(c, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/wooplix_partner_badge.png")
async def get_partner_badge():
    for c in [HERE / "public" / "wooplix_partner_badge.png", HERE / "wooplix_partner_badge.png", HERE.parent / "wooplix_partner_badge.png"]:
        if c.exists():
            return FileResponse(c, media_type="image/png")
    raise HTTPException(status_code=404, detail="Badge not found")


@app.get("/wooplix_logo.png")
async def get_legacy_logo():
    for c in [HERE / "public" / "wooplix_logo.png", HERE / "wooplix_logo.png", HERE.parent / "wooplix_logo.png"]:
        if c.exists():
            return FileResponse(c, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/api/health")
@app.get("/health")
@app.get("/api/index.py")
async def health_check():
    has_groq = bool(os.environ.get("GROQ_API_KEY") or agent.GROQ_API_KEY)
    has_zoho = bool(os.environ.get("ZOHO_CLIENT_ID") or agent.ZOHO_CLIENT_ID)
    return {
        "status": "healthy",
        "groq_configured": has_groq,
        "zoho_env_configured": has_zoho,
        "model": os.environ.get("GROQ_MODEL", agent.GROQ_MODEL),
        "version": "2.0.0"
    }


@app.post("/api/exchange-token")
@app.post("/exchange-token")
async def exchange_token(
    code: str = Form(...),
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
    accounts_url: Optional[str] = Form("https://accounts.zoho.in"),
):
    """Exchange 10-minute Zoho grant token (authorization code) for a permanent refresh token."""
    cid = (client_id or "").strip() or os.environ.get("ZOHO_CLIENT_ID", "")
    csec = (client_secret or "").strip() or os.environ.get("ZOHO_CLIENT_SECRET", "")
    acc = (accounts_url or "").strip() or os.environ.get("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.in")

    if not cid or not csec:
        raise HTTPException(status_code=400, detail="Client ID and Client Secret are required to exchange authorization code.")

    try:
        data = agent.exchange_zoho_grant_code(cid, csec, code, acc)
        return {
            "status": "success",
            "refresh_token": data.get("refresh_token"),
            "access_token": data.get("access_token"),
            "api_domain": data.get("api_domain"),
            "scope": data.get("scope")
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/discover")
@app.post("/discover")
async def discover_environment_endpoint(
    request: Request,
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
    refresh_token: Optional[str] = Form(""),
    token: Optional[str] = Form(""),
    accounts_url: Optional[str] = Form("https://accounts.zoho.in"),
):
    """Inspect environment to auto-detect client organization profile and installed applications."""
    cid = (client_id or "").strip()
    csec = (client_secret or "").strip()
    reftok = (token or refresh_token or "").strip()
    acc = (accounts_url or "").strip()

    if not cid or not csec or not reftok:
        try:
            body = await request.json()
            if isinstance(body, dict):
                cid = cid or body.get("client_id", "")
                csec = csec or body.get("client_secret", "")
                reftok = reftok or body.get("token", "") or body.get("refresh_token", "")
                acc = acc or body.get("accounts_url", "")
        except Exception:
            pass

    cid = cid or os.environ.get("ZOHO_CLIENT_ID", "")
    csec = csec or os.environ.get("ZOHO_CLIENT_SECRET", "")
    reftok = reftok or os.environ.get("ZOHO_REFRESH_TOKEN", "")
    acc = acc or os.environ.get("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.in")

    if not cid or not csec or not reftok:
        return {
            "organization_name": "Wooplix Client Organization",
            "contact_email": "enquiry@wooplix.com",
            "auditor_default": "Ankita Pandey (Zoho Certified Lead)",
            "api_domain": "https://www.zohoapis.in",
            "discovered_apps": [
                {"id": "zoho_crm", "name": "Zoho CRM", "description": "Core Sales, Deals, Pipeline stages, & data hygiene", "status": "active", "status_label": "Probed Baseline", "recommended": True},
                {"id": "zoho_desk", "name": "Zoho Desk", "description": "Department queues, SLAs, & escalation triggers", "status": "active", "status_label": "Probed Baseline", "recommended": True},
                {"id": "zoho_books", "name": "Zoho Books", "description": "Multi-currency, overdue receivables, & invoice flows", "status": "active", "status_label": "Probed Baseline", "recommended": True},
                {"id": "zoho_flow", "name": "Cross-App Sync", "description": "CRM-to-Books/Desk bidirectional synchronization", "status": "recommended", "status_label": "Cross-App Governance", "recommended": True}
            ]
        }

    try:
        data = agent.discover_environment(cid, csec, reftok, acc)
        return data
    except Exception as exc:
        print(f"Discovery probe error: {exc}")
        return {
            "organization_name": "Connected Client Organization",
            "contact_email": "",
            "auditor_default": "Ankita Pandey (Zoho Certified Lead)",
            "api_domain": acc,
            "warning": str(exc),
            "discovered_apps": [
                {"id": "zoho_crm", "name": "Zoho CRM", "description": "Sales pipeline, lead routing, custom fields", "status": "active", "status_label": "Ready for Audit", "recommended": True},
                {"id": "zoho_desk", "name": "Zoho Desk", "description": "Support tickets, queues, and SLAs", "status": "active", "status_label": "Ready for Audit", "recommended": True},
                {"id": "zoho_books", "name": "Zoho Books", "description": "Invoicing, currencies, receivables", "status": "active", "status_label": "Ready for Audit", "recommended": True},
                {"id": "zoho_flow", "name": "Cross-App Sync", "description": "Data synchronization and webhooks", "status": "recommended", "status_label": "Ready for Audit", "recommended": True}
            ]
        }


def _render_audit_pdf(audit_data: dict, target_pdf: Path, host: Optional[str] = None) -> bool:
    """Render PDF deliverable via Vercel PHP Dompdf function or local Dompdf."""
    if os.environ.get("VERCEL"):
        base = host or os.environ.get("VERCEL_PROJECT_PRODUCTION_URL") or os.environ.get("VERCEL_URL")
        token = os.environ.get("PDF_RENDER_TOKEN") or "wooplix-zoho-audit-render-secret-2026"
        if base:
            url = base if base.startswith("http") else f"https://{base}"
            url = f"{url.rstrip('/')}/api/pdf.php"
            try:
                import requests
                r = requests.post(
                    url,
                    json={"html": agent.build_html(audit_data)},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=240,
                )
                if r.status_code == 200 and len(r.content) > 100:
                    target_pdf.write_bytes(r.content)
                    return True
            except Exception as e:
                print(f"Vercel PHP PDF generation warning: {e}")
    try:
        agent.build_pdf(audit_data, str(target_pdf))
        if target_pdf.exists() and target_pdf.stat().st_size > 0:
            return True
    except Exception as pdf_err:
        print(f"Local Dompdf generation warning: {pdf_err}")
    return False


def _extract_telemetry_summary(telemetry: dict, company_name: str, suites_list: list) -> dict:
    meta = telemetry.get("client_metadata", {})
    mode = meta.get("audit_mode", "Live Zoho API Telemetry")
    crm = telemetry.get("zoho_crm", {})
    org_settings = crm.get("org_settings", {})
    edition = org_settings.get("edition") or crm.get("edition") or "Zoho Cloud Suite"

    op_metrics = crm.get("operational_metrics", {})
    deals_sampled = op_metrics.get("deals_sampled")
    if deals_sampled is None:
        deals_sampled = crm.get("data_hygiene", {}).get("dormant_deals_over_90_days", 48)

    leads_sampled = op_metrics.get("leads_sampled")
    if leads_sampled is None:
        leads_sampled = crm.get("data_hygiene", {}).get("total_leads_in_pipeline", 50)

    modules = len(crm.get("modules_inventory", [])) or len(crm.get("installed_modules", [])) or 16

    clean_suites = [s.replace("Zoho ", "").strip() for s in suites_list]
    is_live = "Live" in mode

    return {
        "mode": "Live Zoho REST API (OAuth 2.0)" if is_live else "Sample Diagnostic Baseline",
        "is_live": is_live,
        "organization": company_name,
        "edition": str(edition),
        "deals_inspected": deals_sampled,
        "leads_inspected": leads_sampled,
        "modules_detected": modules,
        "suites": clean_suites
    }


@app.post("/api/audit")
@app.post("/audit")
async def trigger_audit(
    request: Request,
    company_name: Optional[str] = Form(""),
    auditor_name: Optional[str] = Form("Ankita Pandey (Zoho Certified Lead)"),
    contact_email: Optional[str] = Form(""),
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
    token: Optional[str] = Form(""),
    refresh_token: Optional[str] = Form(""),
    accounts_url: Optional[str] = Form("https://accounts.zoho.in"),
    target_suites: Optional[str] = Form("zoho_crm,zoho_desk,zoho_books"),
    use_demo: Optional[bool] = Form(False),
    format: Optional[str] = Query("pdf")
):
    """Run end-to-end Zoho environment audit and return requested deliverable."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    groq_key = os.environ.get("GROQ_API_KEY") or agent.GROQ_API_KEY
    if not groq_key:
        raise HTTPException(
            status_code=503,
            detail="GROQ_API_KEY is not configured on the server. Please check .env configuration."
        )

    # Determine credentials
    cid = (client_id or "").strip() or os.environ.get("ZOHO_CLIENT_ID", "")
    csec = (client_secret or "").strip() or os.environ.get("ZOHO_CLIENT_SECRET", "")
    reftok = (token or refresh_token or "").strip() or os.environ.get("ZOHO_REFRESH_TOKEN", "")
    acc_url = (accounts_url or "").strip() or os.environ.get("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.in")

    # Auto-detect company name if not provided
    comp_name = (company_name or "").strip()
    if not comp_name or comp_name == "Client Organization":
        try:
            disc = agent.discover_environment(cid, csec, reftok, acc_url)
            comp_name = disc.get("organization_name") or "Client Organization"
        except Exception:
            comp_name = "Client Organization"
    company_name = comp_name
    auditor = (auditor_name or "Ankita Pandey (Zoho Certified Lead)").strip()

    # Parse target suites
    suites_list = []
    if target_suites:
        raw_items = [s.strip().lower() for s in target_suites.split(",") if s.strip()]
        for s in raw_items:
            if "crm" in s:
                suites_list.append("Zoho CRM")
            elif "desk" in s:
                suites_list.append("Zoho Desk")
            elif "book" in s or "billing" in s:
                suites_list.append("Zoho Books")
            elif "flow" in s:
                suites_list.append("Zoho Flow")
            elif "creator" in s:
                suites_list.append("Zoho Creator")
            else:
                suites_list.append(s.title())
    if not suites_list:
        suites_list = ["Zoho CRM", "Zoho Desk", "Zoho Books"]

    # Ensure live credentials dictionary is built from user-provided token
    creds = None
    if not use_demo and cid and csec and reftok:
        creds = {
            "client_id": cid,
            "client_secret": csec,
            "refresh_token": reftok,
            "token": reftok,
            "accounts_url": acc_url,
        }

    stem = agent._safe_stem(company_name)

    try:
        with tempfile.TemporaryDirectory(prefix="wooplix-audit-") as work_dir:
            work_path = Path(work_dir)

            # Step 1: Collect Telemetry
            telemetry = agent.collect_environment_telemetry(
                credentials=creds,
                target_suites=suites_list,
                company_name=company_name,
                force_sample=(use_demo or creds is None)
            )

            # Extract live verification telemetry for the web app UI
            tel_summary = _extract_telemetry_summary(telemetry, company_name, suites_list)
            tel_b64 = base64.b64encode(json.dumps(tel_summary, ensure_ascii=False).encode("utf-8")).decode("ascii")

            # Step 2: Diagnostic Analysis via Groq LLM
            audit_data = agent.analyze_telemetry_with_groq(
                telemetry_data=telemetry,
                auditor_name=auditor_name
            )

            health_score = audit_data.get("overall_health_score", 65)

            # Step 3: Compile Deliverables
            docx_file = work_path / f"Wooplix_Audit_{stem}.docx"
            pdf_file  = work_path / f"Wooplix_Audit_{stem}.pdf"
            json_file = work_path / f"Wooplix_Audit_{stem}.json"

            json_file.write_text(json.dumps(audit_data, indent=2, ensure_ascii=False), encoding="utf-8")
            agent.build_docx(audit_data, str(docx_file))

            pdf_generated = _render_audit_pdf(audit_data, pdf_file, host=host)

            req_format = (format or "pdf").lower()

            common_headers = {
                "X-Audit-Client": company_name,
                "X-Audit-Filename": f"Wooplix_Audit_{stem}.pdf" if req_format == "pdf" else f"Wooplix_Audit_{stem}.docx",
                "X-Audit-Score": str(health_score),
                "X-Audit-Type": req_format,
                "X-Audit-Mode": tel_summary["mode"],
                "X-Audit-Telemetry": tel_b64,
            }

            # Stream direct PDF
            if req_format == "pdf" and pdf_generated:
                pdf_bytes = pdf_file.read_bytes()
                out_name = f"Wooplix_Audit_{stem}.pdf"
                common_headers["Content-Disposition"] = f'attachment; filename="{out_name}"'
                common_headers["X-Audit-Filename"] = out_name
                return StreamingResponse(
                    io.BytesIO(pdf_bytes),
                    media_type="application/pdf",
                    headers=common_headers
                )

            # Stream direct DOCX
            if req_format == "docx" or (req_format == "pdf" and not pdf_generated):
                docx_bytes = docx_file.read_bytes()
                out_name = f"Wooplix_Audit_{stem}.docx"
                common_headers["Content-Disposition"] = f'attachment; filename="{out_name}"'
                common_headers["X-Audit-Filename"] = out_name
                common_headers["X-Audit-Type"] = "docx"
                return StreamingResponse(
                    io.BytesIO(docx_bytes),
                    media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers=common_headers
                )

            # Stream complete ZIP package (PDF + DOCX + JSON Telemetry)
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
                if docx_file.exists():
                    bundle.write(docx_file, arcname=f"Wooplix_Audit_{stem}/{docx_file.name}")
                if pdf_file.exists() and pdf_file.stat().st_size > 0:
                    bundle.write(pdf_file, arcname=f"Wooplix_Audit_{stem}/{pdf_file.name}")
                if json_file.exists():
                    bundle.write(json_file, arcname=f"Wooplix_Audit_{stem}/{json_file.name}")

            zip_buffer.seek(0)
            out_name = f"Wooplix_Audit_{stem}_Package.zip"
            common_headers["Content-Disposition"] = f'attachment; filename="{out_name}"'
            common_headers["X-Audit-Filename"] = out_name
            common_headers["X-Audit-Type"] = "zip"
            return StreamingResponse(
                zip_buffer,
                media_type="application/zip",
                headers=common_headers
            )

    except HTTPException:
        raise
    except Exception as exc:
        print(f"Audit generation failed: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=500,
            detail=f"Audit generation failed ({type(exc).__name__}: {str(exc)[:180]})"
        ) from exc


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting Wooplix Zoho Audit Server on http://localhost:{port}")
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
