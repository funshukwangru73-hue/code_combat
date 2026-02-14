"""
ContestGuard — Cloud Relay Server
===================================
Lightweight Flask API. Deploy free on Render / Railway / Fly.io.

Endpoints:
  POST /session/create          Admin creates a session → gets session_id + admin_token
  POST /session/<id>/ips        Admin pushes allowed IP list (requires admin_token)
  GET  /session/<id>/ips        Student fetches allowed IPs (requires session_code)
  GET  /session/<id>/status     Student polls for policy updates (active / ended)
  POST /session/<id>/end        Admin ends the session (requires admin_token)
  POST /session/<id>/log        Student app posts activity log (requires session_code)
  GET  /session/<id>/logs       Admin views student logs (requires admin_token)
  GET  /health                  Health check
"""

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import uuid
import secrets
import time
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# In-memory store (for production use Redis / SQLite)
# Structure: { session_id: { ...session data } }
SESSIONS: dict = {}

# ── Helpers ──────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def get_session(session_id: str):
    s = SESSIONS.get(session_id)
    if not s:
        abort(404, description="Session not found")
    return s

def require_admin(s: dict):
    token = request.headers.get("X-Admin-Token") or request.json.get("admin_token", "") if request.is_json else request.args.get("admin_token", "")
    if not secrets.compare_digest(str(token), str(s["admin_token"])):
        abort(403, description="Invalid admin token")

def require_code(s: dict):
    code = request.headers.get("X-Session-Code") or request.args.get("code", "")
    if not secrets.compare_digest(str(code), str(s["session_code"])):
        abort(403, description="Invalid session code")

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "sessions": len(SESSIONS), "time": now_iso()})


@app.route("/session/create", methods=["POST"])
def create_session():
    """Admin creates a new contest session."""
    data         = request.get_json(silent=True) or {}
    session_id   = str(uuid.uuid4())[:8].upper()          # e.g. "A3F7B2C1"
    admin_token  = secrets.token_hex(24)                   # long secret for admin
    session_code = f"{secrets.randbelow(9000)+1000}"       # 4-digit student code

    SESSIONS[session_id] = {
        "session_id":    session_id,
        "session_code":  session_code,
        "admin_token":   admin_token,
        "contest_name":  data.get("contest_name", "Contest"),
        "allowed_ips":   [],
        "status":        "active",          # active | ended
        "created_at":    now_iso(),
        "ended_at":      None,
        "logs":          [],
        "student_count": 0,
    }

    return jsonify({
        "session_id":   session_id,
        "session_code": session_code,
        "admin_token":  admin_token,
        "message":      "Session created. Share session_id + session_code with students via QR.",
    }), 201


@app.route("/session/<session_id>/ips", methods=["POST"])
def set_ips(session_id):
    """Admin pushes the list of allowed IPs/subnets/domains."""
    s    = get_session(session_id)
    data = request.get_json(silent=True) or {}
    require_admin(s)

    ips = data.get("allowed_ips", [])
    if not isinstance(ips, list):
        abort(400, description="allowed_ips must be a list")

    s["allowed_ips"]  = ips
    s["ips_updated"]  = now_iso()
    return jsonify({"message": "IPs updated", "count": len(ips), "allowed_ips": ips})


@app.route("/session/<session_id>/ips", methods=["GET"])
def get_ips(session_id):
    """Student fetches current allowed IP list."""
    s = get_session(session_id)
    require_code(s)
    s["student_count"] = s.get("student_count", 0) + 1
    return jsonify({
        "session_id":   session_id,
        "contest_name": s["contest_name"],
        "allowed_ips":  s["allowed_ips"],
        "status":       s["status"],
        "updated_at":   s.get("ips_updated", s["created_at"]),
    })


@app.route("/session/<session_id>/status", methods=["GET"])
def get_status(session_id):
    """Student polls for live status + IP changes (lightweight endpoint)."""
    s = get_session(session_id)
    require_code(s)
    return jsonify({
        "status":      s["status"],
        "allowed_ips": s["allowed_ips"],
        "updated_at":  s.get("ips_updated", s["created_at"]),
    })


@app.route("/session/<session_id>/end", methods=["POST"])
def end_session(session_id):
    """Admin ends the session — students will be notified to unlock."""
    s = get_session(session_id)
    require_admin(s)
    s["status"]   = "ended"
    s["ended_at"] = now_iso()
    return jsonify({"message": "Session ended", "ended_at": s["ended_at"]})


@app.route("/session/<session_id>/log", methods=["POST"])
def post_log(session_id):
    """Student app posts activity events."""
    s    = get_session(session_id)
    data = request.get_json(silent=True) or {}
    require_code(s)

    entry = {
        "timestamp":  now_iso(),
        "student_id": data.get("student_id", "unknown"),
        "hostname":   data.get("hostname", ""),
        "event":      data.get("event", ""),
        "detail":     data.get("detail", ""),
    }
    s["logs"].append(entry)
    # Keep last 1000 log entries only
    if len(s["logs"]) > 1000:
        s["logs"] = s["logs"][-1000:]

    return jsonify({"message": "Logged"})


@app.route("/session/<session_id>/logs", methods=["GET"])
def get_logs(session_id):
    """Admin views all student activity logs."""
    s = get_session(session_id)
    require_admin(s)
    return jsonify({
        "session_id":    session_id,
        "contest_name":  s["contest_name"],
        "student_count": s["student_count"],
        "log_count":     len(s["logs"]),
        "logs":          s["logs"],
    })


@app.route("/session/<session_id>/info", methods=["GET"])
def get_info(session_id):
    """Admin views full session info."""
    s = get_session(session_id)
    require_admin(s)
    return jsonify({k: v for k, v in s.items() if k != "admin_token"})


# ── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e)}), 404

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": str(e)}), 403

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    print("ContestGuard Server running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
