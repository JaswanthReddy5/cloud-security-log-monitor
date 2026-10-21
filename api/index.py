"""Vercel Python Function entry point.

Vercel routes /api/* here (see vercel.json). The WSGI `app` object is picked up
by the Vercel Python runtime; Flask then routes on the original request path.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))

from app import create_app  # noqa: E402

app = create_app()
