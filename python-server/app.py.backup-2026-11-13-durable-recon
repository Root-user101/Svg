import os
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KiB request limit


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/lab")
def cyber_lab():
    return render_template("lab.html")


@app.get("/bounty")
def bounty_hq():
    return render_template("bounty.html")


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



import hmac
from functools import wraps
from recon_engine import start_job, get_job, list_jobs

@app.get("/recon")
def recon_studio():
    return render_template("recon.html")

def recon_auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        expected = os.environ.get("RECON_API_KEY", "")
        supplied = request.headers.get("X-Recon-Key", "")
        if not expected:
            return jsonify({"ok": False, "error": "Recon is locked. Set RECON_API_KEY in the Render service environment first."}), 503
        if not hmac.compare_digest(supplied, expected):
            return jsonify({"ok": False, "error": "Invalid recon access key."}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.post("/api/recon/start")
@recon_auth_required
def api_recon_start():
    data = request.get_json(silent=True) or {}
    scope = data.get("scope", [])
    if not isinstance(scope, list) or len(scope) > 30:
        return jsonify({"ok": False, "error": "Provide at most 30 scope entries."}), 400
    try:
        job_id = start_job(data.get("domain", ""), scope, bool(data.get("active_ports", False)))
        return jsonify({"ok": True, "job_id": job_id}), 202
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

@app.get("/api/recon/jobs")
@recon_auth_required
def api_recon_jobs():
    return jsonify({"ok": True, "jobs": list_jobs()})

@app.get("/api/recon/jobs/<job_id>")
@recon_auth_required
def api_recon_job(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Job not found. It may have been cleared by a server restart."}), 404
    return jsonify({"ok": True, "job": job})


if __name__ == "__main__":
    # Local development only. Production uses Gunicorn.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
