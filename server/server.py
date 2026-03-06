"""
ContestGuard — Cloud Relay Server (PRODUCTION READY)
======================================================
Lightweight Flask API. Deploy free on Render / Railway / Fly.io.

IMPROVEMENTS in this version:
  ✓ SQLite persistence (survives restarts)
  ✓ Rate limiting (prevents abuse)
  ✓ Proper logging
  ✓ Better error handling
  ✓ Health check with uptime

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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import secrets
import time
import json
import os
import sqlite3
import logging
from datetime import datetime
from contextlib import contextmanager

app = Flask(__name__)

# Configure CORS (restrict in production if needed)
CORS(app, origins=["*"])  # Change to specific domains in production

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = os.getenv('DB_PATH', '/tmp/contestguard.db')
START_TIME = time.time()

# ── Database Setup ───────────────────────────────────────────────────────────

@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize database schema."""
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                session_code TEXT NOT NULL,
                admin_token TEXT NOT NULL,
                contest_name TEXT NOT NULL,
                allowed_ips TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active',
                created_at TEXT NOT NULL,
                ended_at TEXT,
                student_count INTEGER DEFAULT 0,
                ips_updated TEXT
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                student_id TEXT,
                hostname TEXT,
                event TEXT,
                detail TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_logs_session 
            ON logs(session_id)
        ''')
        
        logger.info(f"Database initialized at {DB_PATH}")

# Initialize database on startup
init_db()

# ── Helpers ──────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def get_session(session_id: str):
    """Fetch session from database."""
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM sessions WHERE session_id = ?',
            (session_id,)
        ).fetchone()
        
        if not row:
            abort(404, description="Session not found")
        
        # Convert row to dict
        session = dict(row)
        session['allowed_ips'] = json.loads(session['allowed_ips'])
        return session

def save_session(session_data: dict):
    """Save or update session in database."""
    with get_db() as conn:
        # Convert allowed_ips to JSON string
        data = session_data.copy()
        data['allowed_ips'] = json.dumps(data.get('allowed_ips', []))
        
        conn.execute('''
            INSERT OR REPLACE INTO sessions 
            (session_id, session_code, admin_token, contest_name, allowed_ips, 
             status, created_at, ended_at, student_count, ips_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['session_id'],
            data['session_code'],
            data['admin_token'],
            data['contest_name'],
            data['allowed_ips'],
            data.get('status', 'active'),
            data['created_at'],
            data.get('ended_at'),
            data.get('student_count', 0),
            data.get('ips_updated')
        ))

def require_admin(session_id: str):
    """Verify admin token."""
    session = get_session(session_id)
    token = request.headers.get("X-Admin-Token") or \
            (request.json.get("admin_token", "") if request.is_json else "") or \
            request.args.get("admin_token", "")
    
    if not secrets.compare_digest(str(token), str(session["admin_token"])):
        logger.warning(f"Invalid admin token for session {session_id}")
        abort(403, description="Invalid admin token")
    
    return session

def require_code(session_id: str):
    """Verify session code."""
    session = get_session(session_id)
    code = request.headers.get("X-Session-Code") or \
           request.args.get("code", "")
    
    if not secrets.compare_digest(str(code), str(session["session_code"])):
        logger.warning(f"Invalid session code for session {session_id}")
        abort(403, description="Invalid session code")
    
    return session

def add_log(session_id: str, student_id: str, hostname: str, event: str, detail: str):
    """Add log entry to database."""
    with get_db() as conn:
        conn.execute('''
            INSERT INTO logs (session_id, timestamp, student_id, hostname, event, detail)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, now_iso(), student_id, hostname, event, detail))
        
        # Keep only last 1000 logs per session
        conn.execute('''
            DELETE FROM logs WHERE id IN (
                SELECT id FROM logs 
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET 1000
            )
        ''', (session_id,))

def get_logs(session_id: str) -> list:
    """Fetch logs for a session."""
    with get_db() as conn:
        rows = conn.execute('''
            SELECT timestamp, student_id, hostname, event, detail
            FROM logs
            WHERE session_id = ?
            ORDER BY timestamp DESC
            LIMIT 1000
        ''', (session_id,)).fetchall()
        
        return [dict(row) for row in rows]

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Health check endpoint for monitoring."""
    try:
        # Quick DB check
        with get_db() as conn:
            session_count = conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
        
        return jsonify({
            "status": "ok",
            "sessions": session_count,
            "uptime_seconds": int(time.time() - START_TIME),
            "time": now_iso()
        }), 200, {'Cache-Control': 'no-cache'}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/session/create", methods=["POST"])
@limiter.limit("10 per minute")  # Prevent spam
def create_session():
    """Admin creates a new contest session."""
    try:
        data         = request.get_json(silent=True) or {}
        session_id   = str(uuid.uuid4())[:8].upper()          # e.g. "A3F7B2C1"
        admin_token  = secrets.token_hex(24)                   # long secret for admin
        session_code = f"{secrets.randbelow(9000)+1000}"       # 4-digit student code

        session_data = {
            "session_id":    session_id,
            "session_code":  session_code,
            "admin_token":   admin_token,
            "contest_name":  data.get("contest_name", "Contest"),
            "allowed_ips":   [],
            "status":        "active",
            "created_at":    now_iso(),
            "ended_at":      None,
            "student_count": 0,
            "ips_updated":   None
        }

        save_session(session_data)
        
        logger.info(f"Session created: {session_id} - {session_data['contest_name']}")

        return jsonify({
            "session_id":   session_id,
            "session_code": session_code,
            "admin_token":  admin_token,
            "message":      "Session created. Share session_id + session_code with students.",
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return jsonify({"error": "Failed to create session"}), 500


@app.route("/session/<session_id>/ips", methods=["POST"])
@limiter.limit("30 per minute")
def set_ips(session_id):
    """Admin pushes the list of allowed IPs/subnets/domains."""
    try:
        session = require_admin(session_id)
        data = request.get_json(silent=True) or {}

        ips = data.get("allowed_ips", [])
        if not isinstance(ips, list):
            abort(400, description="allowed_ips must be a list")

        session["allowed_ips"] = ips
        session["ips_updated"] = now_iso()
        save_session(session)
        
        logger.info(f"Session {session_id}: IPs updated ({len(ips)} entries)")

        return jsonify({
            "message": "IPs updated",
            "count": len(ips),
            "allowed_ips": ips
        })
        
    except Exception as e:
        logger.error(f"Error setting IPs for {session_id}: {e}")
        raise


@app.route("/session/<session_id>/ips", methods=["GET"])
@limiter.limit("60 per minute")
def get_ips(session_id):
    """Student fetches current allowed IP list."""
    try:
        session = require_code(session_id)
        
        # Increment student count
        with get_db() as conn:
            conn.execute('''
                UPDATE sessions 
                SET student_count = student_count + 1
                WHERE session_id = ?
            ''', (session_id,))
        
        return jsonify({
            "session_id":   session_id,
            "contest_name": session["contest_name"],
            "allowed_ips":  session["allowed_ips"],
            "status":       session["status"],
            "updated_at":   session.get("ips_updated") or session["created_at"],
        })
        
    except Exception as e:
        logger.error(f"Error getting IPs for {session_id}: {e}")
        raise


@app.route("/session/<session_id>/status", methods=["GET"])
@limiter.limit("120 per minute")  # Students poll frequently
def get_status(session_id):
    """Student polls for live status + IP changes (lightweight endpoint)."""
    try:
        session = require_code(session_id)
        
        return jsonify({
            "status":      session["status"],
            "allowed_ips": session["allowed_ips"],
            "updated_at":  session.get("ips_updated") or session["created_at"],
        })
        
    except Exception as e:
        logger.error(f"Error getting status for {session_id}: {e}")
        raise


@app.route("/session/<session_id>/end", methods=["POST"])
@limiter.limit("10 per minute")
def end_session(session_id):
    """Admin ends the session — students will be notified to unlock."""
    try:
        session = require_admin(session_id)
        
        session["status"]   = "ended"
        session["ended_at"] = now_iso()
        save_session(session)
        
        logger.info(f"Session {session_id}: Ended by admin")

        return jsonify({
            "message": "Session ended",
            "ended_at": session["ended_at"]
        })
        
    except Exception as e:
        logger.error(f"Error ending session {session_id}: {e}")
        raise


@app.route("/session/<session_id>/log", methods=["POST"])
@limiter.limit("60 per minute")
def post_log(session_id):
    """Student app posts activity events."""
    try:
        session = require_code(session_id)
        data = request.get_json(silent=True) or {}

        add_log(
            session_id,
            data.get("student_id", "unknown"),
            data.get("hostname", ""),
            data.get("event", ""),
            data.get("detail", "")
        )

        return jsonify({"message": "Logged"})
        
    except Exception as e:
        logger.error(f"Error posting log for {session_id}: {e}")
        raise


@app.route("/session/<session_id>/logs", methods=["GET"])
@limiter.limit("30 per minute")
def get_logs_endpoint(session_id):
    """Admin views all student activity logs."""
    try:
        session = require_admin(session_id)
        logs = get_logs(session_id)
        
        return jsonify({
            "session_id":    session_id,
            "contest_name":  session["contest_name"],
            "student_count": session["student_count"],
            "log_count":     len(logs),
            "logs":          logs,
        })
        
    except Exception as e:
        logger.error(f"Error getting logs for {session_id}: {e}")
        raise


@app.route("/session/<session_id>/info", methods=["GET"])
@limiter.limit("30 per minute")
def get_info(session_id):
    """Admin views full session info."""
    try:
        session = require_admin(session_id)
        
        # Remove sensitive admin_token from response
        info = {k: v for k, v in session.items() if k != "admin_token"}
        
        return jsonify(info)
        
    except Exception as e:
        logger.error(f"Error getting info for {session_id}: {e}")
        raise


# ── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e.description)}), 404

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": str(e.description)}), 403

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e.description)}), 400

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please try again later."
    }), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500


# ── Startup ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("ContestGuard Server Starting")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"Flask Environment: {os.getenv('FLASK_ENV', 'development')}")
    logger.info("=" * 60)
    
    app.run(host="0.0.0.0", port=5000, debug=False)
