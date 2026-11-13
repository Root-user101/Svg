"""PostgreSQL persistence for Recon Studio. Requires DATABASE_URL and psycopg."""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row

SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_jobs (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  scope JSONB NOT NULL,
  active_ports BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'queued',
  stage TEXT NOT NULL DEFAULT 'Queued',
  progress INTEGER NOT NULL DEFAULT 0,
  results JSONB NOT NULL DEFAULT '{}'::jsonb,
  events JSONB NOT NULL DEFAULT '[]'::jsonb,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS recon_jobs_created_idx ON recon_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS recon_jobs_status_idx ON recon_jobs(status);

CREATE TABLE IF NOT EXISTS recon_schedules (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  scope JSONB NOT NULL,
  active_ports BOOLEAN NOT NULL DEFAULT FALSE,
  interval_hours INTEGER NOT NULL CHECK (interval_hours IN (6, 12, 24, 168)),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_job_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recon_schedules_due_idx ON recon_schedules(enabled, next_run_at);
"""

def connect():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured.")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return psycopg.connect(url, row_factory=dict_row, connect_timeout=8)

def init_db():
    with connect() as conn:
        conn.execute(SCHEMA)

def create_job(domain, scope, active_ports=False, schedule_id=None):
    job_id = uuid.uuid4().hex[:16]
    with connect() as conn:
        conn.execute(
            """INSERT INTO recon_jobs(id,domain,scope,active_ports)
               VALUES (%s,%s,%s::jsonb,%s)""",
            (job_id, domain, json.dumps(scope), bool(active_ports))
        )
        if schedule_id:
            conn.execute(
                "UPDATE recon_schedules SET last_job_id=%s WHERE id=%s",
                (job_id, schedule_id)
            )
    return job_id

def get_job(job_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM recon_jobs WHERE id=%s", (job_id,)).fetchone()
    return _jsonable(row) if row else None

def list_jobs(limit=30):
    with connect() as conn:
        rows = conn.execute(
            "SELECT id,domain,status,stage,progress,created_at FROM recon_jobs ORDER BY created_at DESC LIMIT %s",
            (limit,)
        ).fetchall()
    return [_jsonable(row) for row in rows]

def update_job(job_id, **fields):
    allowed = {"status", "stage", "progress", "results", "events", "error", "completed_at"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return
    assignments, values = [], []
    for key, value in fields.items():
        if key in ("results", "events"):
            assignments.append(f"{key}=%s::jsonb")
            values.append(json.dumps(value))
        else:
            assignments.append(f"{key}=%s")
            values.append(value)
    assignments.append("updated_at=NOW()")
    values.append(job_id)
    with connect() as conn:
        conn.execute(f"UPDATE recon_jobs SET {', '.join(assignments)} WHERE id=%s", values)

def create_schedule(domain, scope, active_ports, interval_hours):
    if interval_hours not in (6, 12, 24, 168):
        raise ValueError("Schedule interval must be 6, 12, 24 or 168 hours.")
    schedule_id = uuid.uuid4().hex[:16]
    with connect() as conn:
        conn.execute(
            """INSERT INTO recon_schedules(id,domain,scope,active_ports,interval_hours)
               VALUES (%s,%s,%s::jsonb,%s,%s)""",
            (schedule_id, domain, json.dumps(scope), bool(active_ports), interval_hours)
        )
    return schedule_id

def list_schedules():
    with connect() as conn:
        rows = conn.execute("SELECT * FROM recon_schedules ORDER BY created_at DESC").fetchall()
    return [_jsonable(row) for row in rows]

def set_schedule_enabled(schedule_id, enabled):
    with connect() as conn:
        cur = conn.execute("UPDATE recon_schedules SET enabled=%s WHERE id=%s", (bool(enabled), schedule_id))
        return cur.rowcount > 0

def enqueue_due_schedules():
    now = datetime.now(timezone.utc)
    created = []
    with connect() as conn:
        rows = conn.execute(
            """SELECT * FROM recon_schedules
               WHERE enabled=TRUE AND next_run_at <= %s
               ORDER BY next_run_at ASC LIMIT 10
               FOR UPDATE SKIP LOCKED""",
            (now,)
        ).fetchall()
        for row in rows:
            active = conn.execute(
                "SELECT 1 FROM recon_jobs WHERE domain=%s AND status IN ('queued','running') LIMIT 1",
                (row["domain"],)
            ).fetchone()
            if not active:
                job_id = uuid.uuid4().hex[:16]
                conn.execute(
                    """INSERT INTO recon_jobs(id,domain,scope,active_ports)
                       VALUES (%s,%s,%s,%s)""",
                    (job_id, row["domain"], json.dumps(row["scope"]), row["active_ports"])
                )
                conn.execute("UPDATE recon_schedules SET last_job_id=%s WHERE id=%s", (job_id, row["id"]))
                created.append(job_id)
            conn.execute(
                "UPDATE recon_schedules SET next_run_at=%s WHERE id=%s",
                (now + timedelta(hours=row["interval_hours"]), row["id"])
            )
    return created

def claim_job():
    with connect() as conn:
        row = conn.execute(
            """SELECT * FROM recon_jobs WHERE status='queued'
               ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED"""
        ).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE recon_jobs SET status='running',stage='Starting worker',updated_at=NOW() WHERE id=%s",
            (row["id"],)
        )
        row["status"] = "running"
    return _jsonable(row)

def _jsonable(row):
    if not row:
        return None
    out = dict(row)
    for key in ("created_at", "updated_at", "completed_at", "next_run_at"):
        if key in out and out[key] is not None:
            out[key] = out[key].isoformat()
    return out
