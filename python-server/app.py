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


if __name__ == "__main__":
    # Local development only. Production uses Gunicorn.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
