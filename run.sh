#!/usr/bin/env bash
# Wooplix Zoho System Audit Agent — Startup Script
set -e

PORT="${PORT:-8000}"
echo "========================================================"
echo "  Wooplix Technologies — Zoho System Audit Agent v2.0"
echo "  Authorized Zoho Partner Automated Diagnostic Engine"
echo "========================================================"
echo ""
echo "Starting local server on http://localhost:${PORT} ..."
echo "Press Ctrl+C to stop."
echo ""

exec python3 app.py
