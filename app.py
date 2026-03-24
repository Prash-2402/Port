"""
app.py — Production Flask backend for Port Scanner + Vulnerability Reporter
"""

import json
import os
import queue
import re
import secrets
import threading
import time
import ipaddress
from datetime import datetime

from flask import (
    Flask, render_template, request, jsonify,
    Response, stream_with_context, session,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import scanner as sc

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# ── In-memory scan sessions {scan_id: {q, done, error}} ──────────────────────
_sessions: dict = {}
_sessions_lock = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────
TARGET_RE = re.compile(r'^[A-Za-z0-9.\-]+$')

PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def _json_error(msg: str, status: int = 400):
    return jsonify({"error": msg}), status


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/agree", methods=["POST"])
def agree():
    """Mark the disclaimer as accepted in the signed session cookie."""
    session["disclaimer_accepted"] = True
    session.permanent = False
    return jsonify({"ok": True})


@app.route("/scan", methods=["POST"])
@limiter.limit(
    "1 per 60 seconds",
    error_message=json.dumps({"error": "Too many requests. Please wait 60 seconds."}),
)
def start_scan():
    # ── Disclaimer check (server-side) ────────────────────────────────
    if not session.get("disclaimer_accepted"):
        return _json_error("You must accept the disclaimer before scanning.", 403)

    data = request.get_json(force=True, silent=True) or {}

    # ── Input validation ──────────────────────────────────────────────
    target = str(data.get("target", "")).strip()
    if not target:
        return _json_error("Target must not be empty.")
    if not TARGET_RE.match(target):
        return _json_error("Target contains invalid characters. Only letters, numbers, dots, and hyphens are allowed.")

    try:
        start_port = int(data.get("start_port", 1))
        end_port   = int(data.get("end_port", 1024))
    except (TypeError, ValueError):
        return _json_error("Port values must be integers.")

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        return _json_error("Ports must be between 1 and 65535.")
    if start_port >= end_port:
        return _json_error("Start port must be less than end port.")
    if (end_port - start_port + 1) > 1000:
        return _json_error("Maximum port range is 1000 ports per scan.")

    # ── Resolve target ────────────────────────────────────────────────
    try:
        ip = sc.resolve_target(target)
    except ValueError as e:
        return _json_error(str(e))

    # ── Block private/reserved IPs ────────────────────────────────────
    if is_private(ip):
        return _json_error("Private IPs are not allowed on this public tool.", 403)

    # ── Create scan session ───────────────────────────────────────────
    scan_id = secrets.token_urlsafe(12)
    q: queue.Queue = queue.Queue()

    with _sessions_lock:
        _sessions[scan_id] = {
            "q":     q,
            "done":  False,
            "error": None,
            "ip":    ip,
            "start": start_port,
            "end":   end_port,
        }

    # ── Background scan thread ────────────────────────────────────────
    def _run():
        t0 = time.perf_counter()
        try:
            def _progress(pct: int):
                q.put({"percent": pct})

            open_ports = sc.scan_all_ports(
                ip, start_port, end_port,
                progress_callback=_progress,
                deadline=30.0,
            )
            results  = sc.build_report(ip, open_ports)
            elapsed  = round(time.perf_counter() - t0, 2)
            q.put({"done": True, "results": results, "elapsed": elapsed,
                   "total": end_port - start_port + 1, "ip": ip})

        except TimeoutError:
            q.put({"error": "Scan timed out. Try a smaller port range."})
        except Exception as exc:
            q.put({"error": f"Scan failed: {exc}"})
        finally:
            with _sessions_lock:
                if scan_id in _sessions:
                    _sessions[scan_id]["done"] = True

    threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "scan_id":    scan_id,
        "ip":         ip,
        "start_port": start_port,
        "end_port":   end_port,
        "total":      end_port - start_port + 1,
    })


@app.route("/stream/<scan_id>")
def stream(scan_id: str):
    """SSE endpoint — streams {percent}, {done, results, elapsed}, or {error}."""
    with _sessions_lock:
        sess = _sessions.get(scan_id)

    if not sess:
        def _err():
            yield 'data: ' + json.dumps({"error": "Unknown scan ID."}) + '\n\n'
        return Response(stream_with_context(_err()), mimetype="text/event-stream")

    def _generate():
        q = sess["q"]
        try:
            while True:
                try:
                    msg = q.get(timeout=35)
                except queue.Empty:
                    yield ': ping\n\n'
                    break

                yield 'data: ' + json.dumps(msg) + '\n\n'

                if "done" in msg or "error" in msg:
                    break
        finally:
            # Clean up session after a delay so late SSE consumers can reconnect
            def _cleanup():
                time.sleep(10)
                with _sessions_lock:
                    _sessions.pop(scan_id, None)
            threading.Thread(target=_cleanup, daemon=True).start()

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Rate-limit error handler ──────────────────────────────────────────────────
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please wait 60 seconds."}), 429


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
