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
    expose_headers=["Content-Disposition", "X-Audit-Client", "X-Audit-Filename", "X-Audit-Score", "X-Audit-Type"]
)


@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
@app.get("/api/index.py", response_class=HTMLResponse)
@app.get("/api/index.py/", response_class=HTMLResponse)
async def serve_portal():
    candidates = [
        HERE / "index.html",
        HERE / "public" / "index.html",
        HERE.parent / "index.html",
        HERE.parent / "public" / "index.html",
        Path("index.html"),
        Path("public/index.html"),
    ]
    for c in candidates:
        if c.exists():
            return HTMLResponse(content=c.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Wooplix Zoho System Audit Agent</h1>")


@app.get("/wooplix_main_logo.png")
@app.get("/api/index.py/wooplix_main_logo.png")
async def get_main_logo():
    for c in [HERE / "wooplix_main_logo.png", HERE / "public" / "wooplix_main_logo.png", HERE.parent / "wooplix_main_logo.png"]:
        if c.exists():
            return FileResponse(c, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/wooplix_partner_badge.png")
@app.get("/api/index.py/wooplix_partner_badge.png")
async def get_partner_badge():
    for c in [HERE / "wooplix_partner_badge.png", HERE / "public" / "wooplix_partner_badge.png", HERE.parent / "wooplix_partner_badge.png"]:
        if c.exists():
            return FileResponse(c, media_type="image/png")
    raise HTTPException(status_code=404, detail="Badge not found")


@app.get("/wooplix_logo.png")
@app.get("/api/index.py/wooplix_logo.png")
async def get_legacy_logo():
    for c in [HERE / "wooplix_logo.png", HERE / "public" / "wooplix_logo.png", HERE.parent / "wooplix_logo.png"]:
        if c.exists():
            return FileResponse(c, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/api/health")
@app.get("/health")
@app.get("/api/index.py/api/health")
@app.get("/api/index.py/health")
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


@app.post("/api/audit")
@app.post("/audit")
@app.post("/api/index.py/api/audit")
@app.post("/api/index.py/audit")
@app.post("/api/index.py")
async def trigger_audit(
    request: Request,
    company_name: str = Form("Client Organization"),
    auditor_name: str = Form("Lead Systems Auditor"),
    contact_email: str = Form(""),
    client_id: Optional[str] = Form(""),
    client_secret: Optional[str] = Form(""),
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

    # Determine credentials
    cid = (client_id or "").strip() or os.environ.get("ZOHO_CLIENT_ID", "")
    csec = (client_secret or "").strip() or os.environ.get("ZOHO_CLIENT_SECRET", "")
    reftok = (refresh_token or "").strip() or os.environ.get("ZOHO_REFRESH_TOKEN", "")
    acc_url = (accounts_url or "").strip() or os.environ.get("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.in")

    creds = None
    if not use_demo and cid and csec and reftok:
        creds = {
            "client_id": cid,
            "client_secret": csec,
            "refresh_token": reftok,
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

            # Stream direct PDF
            if req_format == "pdf" and pdf_generated:
                pdf_bytes = pdf_file.read_bytes()
                out_name = f"Wooplix_Audit_{stem}.pdf"
                return StreamingResponse(
                    io.BytesIO(pdf_bytes),
                    media_type="application/pdf",
                    headers={
                        "Content-Disposition": f'attachment; filename="{out_name}"',
                        "X-Audit-Client": company_name,
                        "X-Audit-Filename": out_name,
                        "X-Audit-Score": str(health_score),
                        "X-Audit-Type": "pdf",
                    }
                )

            # Stream direct DOCX
            if req_format == "docx" or (req_format == "pdf" and not pdf_generated):
                docx_bytes = docx_file.read_bytes()
                out_name = f"Wooplix_Audit_{stem}.docx"
                return StreamingResponse(
                    io.BytesIO(docx_bytes),
                    media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={
                        "Content-Disposition": f'attachment; filename="{out_name}"',
                        "X-Audit-Client": company_name,
                        "X-Audit-Filename": out_name,
                        "X-Audit-Score": str(health_score),
                        "X-Audit-Type": "docx",
                    }
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
            return StreamingResponse(
                zip_buffer,
                media_type="application/zip",
                headers={
                    "Content-Disposition": f'attachment; filename="{out_name}"',
                    "X-Audit-Client": company_name,
                    "X-Audit-Filename": out_name,
                    "X-Audit-Score": str(health_score),
                    "X-Audit-Type": "zip",
                }
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
