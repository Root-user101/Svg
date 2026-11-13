-- Run this once in Supabase SQL Editor.
CREATE TABLE IF NOT EXISTS public.recon_jobs (
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
CREATE INDEX IF NOT EXISTS recon_jobs_created_idx ON public.recon_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS recon_jobs_status_idx ON public.recon_jobs(status);

CREATE TABLE IF NOT EXISTS public.recon_schedules (
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
CREATE INDEX IF NOT EXISTS recon_schedules_due_idx ON public.recon_schedules(enabled, next_run_at);

-- These tables are accessed only by the Flask server and GitHub Actions worker
-- through the database connection string. Do not expose the database password.
