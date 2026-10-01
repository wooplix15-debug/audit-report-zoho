#!/usr/bin/env python3
"""Vercel entrypoint for Wooplix Zoho System Audit Agent."""

import os
import sys
from pathlib import Path

# Add project root to sys.path so app and zoho_audit_agent are importable
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import app
