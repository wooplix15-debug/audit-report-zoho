#!/usr/bin/env python3
"""FastAPI Application for Wooplix Zoho System Audit Agent.

Serves the intake portal and provides API endpoints to trigger automated
Zoho diagnostic telemetry collection, LLM analysis via Groq, and deliverable export.
"""

import io
import os
import re
import json
import zipfile
import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Request, HTTPException, Form, Query
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import zoho_audit_agent as agent

HERE = Path(__file__).resolve().parent

app = FastAPI(
    title="Wooplix Zoho System Audit Agent",
    description="Automated diagnostic engine and audit deliverable generator for Zoho cloud suites.",
    version="2.0.0"
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
    response = await call_next(request)
    if request.scope["path"].startswith("/api/") or request.scope["path"] in ("/audit", "/exchange-token", "/discover"):
        response.headers["Cache-Control"] = "no-store"
    return response


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
def exchange_token(
    code: str = Form(...),
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
    accounts_url: Optional[str] = Form("https://accounts.zoho.in"),
):
    """Exchange 10-minute Zoho grant token (authorization code) for a permanent refresh token."""
    cid = (client_id or "").strip()
    csec = (client_secret or "").strip()
    acc = (accounts_url or "").strip() or os.environ.get("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.in")

    if not cid or not csec:
        raise HTTPException(status_code=400, detail="Client ID and Client Secret are required to exchange authorization code.")

    try:
        data = agent.exchange_zoho_grant_code(cid, csec, code, acc)
        return {
            "status": "success",
            "refresh_token": data.get("refresh_token"),
            "scope": data.get("scope")
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/discover")
@app.post("/discover")
def discover_environment_endpoint(
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
        raise HTTPException(status_code=400, detail="Client ID, Client Secret, and Refresh Token are required for discovery.")
    acc = acc or "https://accounts.zoho.in"

    try:
        data = agent.discover_environment(cid, csec, reftok, acc)
        return data
    except Exception:
        raise HTTPException(status_code=502, detail="Zoho discovery failed. Check the account region, refresh token, and granted scopes.") from None


@app.post("/api/token/exchange")
def exchange_and_save_token(
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
    token: Optional[str] = Form(""),
    accounts_url: Optional[str] = Form("https://accounts.zoho.in"),
):
    """Exchange a one-time Zoho authorization code and return its refresh token."""
    cid = (client_id or "").strip()
    csec = (client_secret or "").strip()
    code = (token or "").strip()
    acc = (accounts_url or "https://accounts.zoho.in").strip()

    if not cid or not csec or not code:
        raise HTTPException(
            status_code=400,
            detail="Client ID, Client Secret, and a fresh Zoho authorization code are required."
        )

    try:
        data = agent.exchange_zoho_grant_code(cid, csec, code, acc)

        return {
            "status": "success",
            "message": "Zoho authorization code exchanged successfully.",
            "refresh_token": data["refresh_token"],
        }
    except Exception as exc:
        raise HTTPException(
            status_code=400 if isinstance(exc, ValueError) else 502,
            detail=str(exc) if isinstance(exc, ValueError) else "Zoho token exchange failed. Check the region, client credentials, and code, then try a newly generated code."
        ) from None


def _render_audit_pdf(audit_data: dict, target_pdf: Path) -> bool:
    """Render PDF deliverable via Vercel PHP Dompdf function or local Dompdf."""
    if os.environ.get("VERCEL"):
        # Use Vercel's deployment URL. Request Host headers are user controlled
        # and must never receive the renderer token or report contents.
        base = os.environ.get("VERCEL_URL") or os.environ.get("VERCEL_PROJECT_PRODUCTION_URL")
        token = os.environ.get("PDF_RENDER_TOKEN", "")
        if base and token:
            url = base if base.startswith("http") else f"https://{base}"
            url = f"{url.rstrip('/')}/api/pdf.php"
            try:
                import requests
                r = requests.post(
                    url,
                    json={"html": agent.build_html(audit_data)},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=240,
                    allow_redirects=False,
                )
                if r.status_code == 200 and r.content.startswith(b"%PDF"):
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
    leads_sampled = op_metrics.get("leads_sampled")
    modules_inventory = crm.get("modules_inventory")
    if modules_inventory is None:
        modules_inventory = crm.get("installed_modules")
    modules = (sum(1 for item in modules_inventory if (isinstance(item, dict) and item.get("api_name")) or isinstance(item, str))
               if isinstance(modules_inventory, list) else None)
    if modules == 0:
        modules = None

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
def trigger_audit(
    company_name: Optional[str] = Form(""),
    auditor_name: Optional[str] = Form("Rahul (Zoho Certified Lead)"),
    contact_email: Optional[str] = Form(""),
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
    token: Optional[str] = Form(""),
    refresh_token: Optional[str] = Form(""),
    accounts_url: Optional[str] = Form("https://accounts.zoho.in"),
    target_suites: Optional[str] = Form("zoho_crm"),
    use_demo: Optional[bool] = Form(False),
    format: Optional[str] = Query("pdf")
):
    """Run end-to-end Zoho environment audit and return requested deliverable."""
    req_format = (format or "pdf").strip().lower()
    if req_format not in {"pdf", "docx", "zip"}:
        raise HTTPException(status_code=400, detail="Choose PDF, Word, or ZIP as the report format.")
    if use_demo and os.environ.get("VERCEL") and os.environ.get("ENABLE_DEMO_AUDIT") != "1":
        raise HTTPException(status_code=403, detail="Sample audits are disabled on this deployment.")
    # Public requests only use credentials explicitly provided for this audit.
    cid = (client_id or "").strip()
    csec = (client_secret or "").strip()
    reftok = (token or refresh_token or "").strip()
    acc_url = (accounts_url or "").strip() or "https://accounts.zoho.in"
    if not use_demo and not (cid and csec and reftok):
        raise HTTPException(status_code=400, detail="Client ID, Client Secret, and a Zoho refresh token are required for a live audit.")

    groq_key = os.environ.get("GROQ_API_KEY") or agent.GROQ_API_KEY
    if not groq_key:
        raise HTTPException(
            status_code=503,
            detail="AI analysis is not configured on the server. Please check deployment configuration."
        )

    comp_name = (company_name or "").strip()
    if not comp_name or comp_name == "Client Organization":
        comp_name = "Client Organization"
    company_name = comp_name
    auditor = (auditor_name or "Rahul (Zoho Certified Lead)").strip()

    # Parse target suites or auto-discover all active tools
    suites_list = []
    supported_suites = {
        "crm": "Zoho CRM", "zoho_crm": "Zoho CRM",
        "desk": "Zoho Desk", "zoho_desk": "Zoho Desk",
        "books": "Zoho Books", "zoho_books": "Zoho Books",
        "inventory": "Zoho Inventory", "zoho_inventory": "Zoho Inventory",
        "projects": "Zoho Projects", "zoho_projects": "Zoho Projects",
        "workdrive": "Zoho WorkDrive", "zoho_workdrive": "Zoho WorkDrive",
        "flow": "Zoho Flow", "zoho_flow": "Zoho Flow",
        "analytics": "Zoho Analytics", "zoho_analytics": "Zoho Analytics",
    }
    if target_suites:
        raw_items = [s.strip().lower() for s in target_suites.split(",") if s.strip()]
        unsupported = [s for s in raw_items if s not in supported_suites]
        if unsupported:
            raise HTTPException(status_code=400, detail="One or more selected applications are not supported for live auditing yet.")
        suites_list = list(dict.fromkeys(supported_suites[s] for s in raw_items))

    if not suites_list:
        raise HTTPException(status_code=400, detail="Select at least one supported application to audit.")

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

            if not company_name or company_name == "Client Organization":
                company_name = (telemetry.get("zoho_crm", {}).get("org_settings", {}).get("company_name")
                                or telemetry.get("client_metadata", {}).get("company_name")
                                or "Client Organization")

            if creds:
                suite_keys = ["zoho_" + s.removeprefix("Zoho ").lower().replace(" ", "_") for s in suites_list]
                accessible = [key for key in suite_keys if telemetry.get(key, {}).get("status") in ("connected", "partial_access")]
                if not accessible:
                    raise HTTPException(status_code=502, detail="Zoho authentication succeeded, but none of the selected apps returned auditable telemetry. Check the granted read scopes and app availability.")

            stem = agent._safe_stem(company_name)

            # Extract live verification telemetry for the web app UI
            tel_summary = _extract_telemetry_summary(telemetry, company_name, suites_list)

            # Step 2: Diagnostic Analysis via Groq LLM
            audit_data = agent.analyze_telemetry_with_groq(
                telemetry_data=telemetry,
                auditor_name=auditor_name
            )
            if not audit_data.get("app_audits"):
                raise HTTPException(status_code=502, detail="AI analysis returned no evidence-backed assessments for the selected applications. No report was generated.")
            audit_data["telemetry_provenance"] = tel_summary

            # Step 3: Compile Deliverables
            docx_file = work_path / f"Wooplix_Audit_{stem}.docx"
            pdf_file  = work_path / f"Wooplix_Audit_{stem}.pdf"
            json_file = work_path / f"Wooplix_Audit_Report_{stem}.json"
            raw_tel_file = work_path / f"Wooplix_Raw_Telemetry_{stem}.json"

            if req_format == "zip":
                json_file.write_text(json.dumps(audit_data, indent=2, ensure_ascii=False), encoding="utf-8")
                raw_tel_file.write_text(json.dumps(telemetry, indent=2, ensure_ascii=False), encoding="utf-8")
            if req_format in {"docx", "zip"}:
                agent.build_docx(audit_data, str(docx_file))
            if req_format in {"pdf", "zip"} and not _render_audit_pdf(audit_data, pdf_file):
                raise HTTPException(status_code=502, detail="PDF rendering is unavailable. Please retry the audit.")

            common_headers = {
                "X-Audit-Filename": f"Wooplix_Audit_{stem}.pdf" if req_format == "pdf" else f"Wooplix_Audit_{stem}.docx",
                "X-Audit-Type": req_format,
                "X-Audit-Mode": tel_summary["mode"],
            }

            # Stream direct PDF
            if req_format == "pdf":
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
            if req_format == "docx":
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

            # Stream complete ZIP package (PDF + DOCX + Audit Report JSON + Raw Telemetry JSON)
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
                if docx_file.exists():
                    bundle.write(docx_file, arcname=f"Wooplix_Audit_{stem}/{docx_file.name}")
                if pdf_file.exists() and pdf_file.stat().st_size > 0:
                    bundle.write(pdf_file, arcname=f"Wooplix_Audit_{stem}/{pdf_file.name}")
                if json_file.exists():
                    bundle.write(json_file, arcname=f"Wooplix_Audit_{stem}/{json_file.name}")
                if raw_tel_file.exists():
                    bundle.write(raw_tel_file, arcname=f"Wooplix_Audit_{stem}/{raw_tel_file.name}")

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
    except agent.ZohoTelemetryError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    except Exception as exc:
        print(f"Audit generation failed: {type(exc).__name__}")
        raise HTTPException(
            status_code=500,
            detail="Audit generation failed before a report was produced. Check server configuration and retry."
        ) from exc


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting Wooplix Zoho Audit Server on http://localhost:{port}")
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
