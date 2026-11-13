"""One-shot worker invoked by GitHub Actions on a schedule or manual dispatch."""
import json
import os
import sys
import time
from datetime import datetime, timezone

from recon_db import claim_job, enqueue_due_schedules, init_db, update_job
from recon_engine import start_job, get_job

MAX_JOBS_PER_RUN = int(os.environ.get("RECON_MAX_JOBS_PER_RUN", "2"))
MAX_RUNTIME_SECONDS = int(os.environ.get("RECON_MAX_RUNTIME_SECONDS", "1200"))

def main():
    init_db()
    created = enqueue_due_schedules()
    if created:
        print("Queued scheduled jobs:", ", ".join(created))

    started = time.monotonic()
    processed = 0
    while processed < MAX_JOBS_PER_RUN and time.monotonic() - started < MAX_RUNTIME_SECONDS:
        row = claim_job()
        if not row:
            break
        job_id = row["id"]
        print("Starting job", job_id, row["domain"])
        try:
            memory_id = start_job(row["domain"], row["scope"], row["active_ports"])
            while time.monotonic() - started < MAX_RUNTIME_SECONDS:
                snapshot = get_job(memory_id)
                if snapshot:
                    update_job(
                        job_id,
                        status=snapshot.get("status", "running"),
                        stage=snapshot.get("stage", "Running"),
                        progress=int(snapshot.get("progress", 0)),
                        results=snapshot.get("results", {}),
                        events=snapshot.get("events", []),
                        error=snapshot.get("error"),
                        completed_at=snapshot.get("completed_at")
                    )
                    if snapshot.get("status") in ("completed", "failed"):
                        break
                time.sleep(3)
            else:
                update_job(job_id, status="queued", stage="Worker time limit reached; will retry", progress=0)
        except Exception as exc:
            update_job(job_id, status="failed", stage="Worker error", error=str(exc)[:500],
                       completed_at=datetime.now(timezone.utc))
            print("Job failed:", str(exc))
        processed += 1
    print("Worker finished. Jobs processed:", processed)

if __name__ == "__main__":
    main()
