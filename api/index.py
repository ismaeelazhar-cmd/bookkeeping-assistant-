"""Vercel's Python runtime looks for a WSGI-compatible `app` object exported from a file under
/api — this just imports the real Flask app from server.py at the repo root and re-exports it,
rather than duplicating any application code here. server.py itself is otherwise host-agnostic
(env-gated for VERCEL/CRON_SECRET/BLOB_READ_WRITE_TOKEN/DATABASE_MODE) — this file's only job is
satisfying Vercel's expected entrypoint location."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import app  # noqa: E402
