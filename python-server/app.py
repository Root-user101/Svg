import os
import hmac
from functools import wraps

from flask import Flask, jsonify, request, render_template

from recon_engine import clean_host, in_scope
from recon_db import create_job, get_job, list_jobs, create_schedule, list_schedules, set_schedule_enabled

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/lab")
def cyber_lab():
    return render_template("lab.html")


@app.get("/bounty")
def bounty_hq():
    return render_template("bounty.html")


@app.get("/recon")
def recon_studio():
    return render_template("recon.html")


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "python-server"})


@app.post("/echo")
def echo():
    return jsonify({
        "ok": True,
        "content_type": request.content_type,
        "json": request.get_json(silent=True),
        "body": request.get_data(as_text=True) if not request.is_json else None
    })


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"ok": False, "error": "Request body exceeds 64 KiB"}), 413


def recon_auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        expected = os.environ.get("RECON_API_KEY", "")
        supplied = request.headers.get("X-Recon-Key", "")
        if not expected:
            return jsonify({"ok": False, "error": "Recon is locked. Configure RECON_API_KEY in Render."}), 503
        if not hmac.compare_digest(supplied, expected):
            return jsonify({"ok": False, "error": "Invalid recon access key."}), 401
        if not os.environ.get("DATABASE_URL"):
            return jsonify({"ok": False, "error": "Database is not connected. Configure DATABASE_URL in Render."}), 503
        return fn(*args, **kwargs)
    return wrapper


def validate_target(data):
    domain = clean_host(data.get("domain", ""))
    scope = data.get("scope", [])
    if not isinstance(scope, list) or not 1 <= len(scope) <= 30:
        raise ValueError("Provide between 1 and 30 authorized scope entries.")
    normalized = []
    for item in scope:
        if not isinstance(item, dict):
            continue
        host = clean_host(item.get("host", ""))
        kind = item.get("type", "Exact hostname")
        if kind not in ("Wildcard domain", "Exact hostname", "API", "Mobile app", "Other"):
            raise ValueError("Unsupported scope asset type.")
        normalized.append({"host": host, "type": kind})
    if not normalized or not in_scope(domain, normalized):
        raise ValueError("The root domain must match one of the supplied scope entries.")
    return domain, normalized


@app.post("/api/recon/start")
@recon_auth_required
def api_recon_start():
    data = request.get_json(silent=True) or {}
    try:
        domain, scope = validate_target(data)
        job_id = create_job(domain, scope, bool(data.get("active_ports", False)))
        return jsonify({"ok": True, "job_id": job_id, "status": "queued"}), 202
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Could not queue recon job")
        return jsonify({"ok": False, "error": "Could not save job. Check database configuration."}), 503


@app.get("/api/recon/jobs")
@recon_auth_required
def api_recon_jobs():
    try:
        return jsonify({"ok": True, "jobs": list_jobs()})
    except Exception:
        app.logger.exception("Could not list recon jobs")
        return jsonify({"ok": False, "error": "Database unavailable."}), 503


@app.get("/api/recon/jobs/<job_id>")
@recon_auth_required
def api_recon_job(job_id):
    try:
        job = get_job(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Job not found."}), 404
        return jsonify({"ok": True, "job": job})
    except Exception:
        app.logger.exception("Could not read recon job")
        return jsonify({"ok": False, "error": "Database unavailable."}), 503


@app.get("/api/recon/schedules")
@recon_auth_required
def api_recon_schedules():
    try:
        return jsonify({"ok": True, "schedules": list_schedules()})
    except Exception:
        app.logger.exception("Could not list schedules")
        return jsonify({"ok": False, "error": "Database unavailable."}), 503


@app.post("/api/recon/schedules")
@recon_auth_required
def api_recon_create_schedule():
    data = request.get_json(silent=True) or {}
    try:
        domain, scope = validate_target(data)
        interval = int(data.get("interval_hours", 24))
        schedule_id = create_schedule(domain, scope, bool(data.get("active_ports", False)), interval)
        return jsonify({"ok": True, "schedule_id": schedule_id}), 201
    except (ValueError, TypeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception:
        app.logger.exception("Could not create recon schedule")
        return jsonify({"ok": False, "error": "Could not save schedule. Check database configuration."}), 503


@app.post("/api/recon/schedules/<schedule_id>/toggle")
@recon_auth_required
def api_recon_toggle_schedule(schedule_id):
    data = request.get_json(silent=True) or {}
    try:
        changed = set_schedule_enabled(schedule_id, bool(data.get("enabled", False)))
        if not changed:
            return jsonify({"ok": False, "error": "Schedule not found."}), 404
        return jsonify({"ok": True})
    except Exception:
        app.logger.exception("Could not update recon schedule")
        return jsonify({"ok": False, "error": "Database unavailable."}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
