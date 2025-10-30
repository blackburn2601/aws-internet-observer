# app.py
import os
import time
import sqlite3
import requests
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify, g
from apscheduler.schedulers.background import BackgroundScheduler
import socket

DB_PATH = os.environ.get("DB_PATH", "monitor.db")
API_TOKEN = os.environ.get("API_TOKEN", "change_this_to_a_random_token")
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "60"))  # change as desired
HTTP_CHECK_PATH = os.environ.get("HTTP_CHECK_PATH", "/health")  # if home hosts a health endpoint

app = Flask(__name__)

# --- DB helpers ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS ip_current (
      id INTEGER PRIMARY KEY,
      ip TEXT,
      updated_at TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS checks (
      id INTEGER PRIMARY KEY,
      ip TEXT,
      time TIMESTAMP,
      reachable INTEGER,
      method TEXT,
      detail TEXT
    );
    """)
    db.commit()
    db.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# --- API endpoint to update IP ---
@app.route("/api/update-ip", methods=["POST"])
def update_ip():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth.split(" ",1)[1] != API_TOKEN:
        return jsonify({"error":"unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or request.remote_addr
    if not ip:
        return jsonify({"error":"no ip provided"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT OR REPLACE INTO ip_current (id, ip, updated_at) VALUES (1, ?, ?)", (ip, datetime.utcnow()))
    db.commit()
    return jsonify({"ok":True, "ip":ip, "ts":datetime.utcnow().isoformat()}), 200

# --- Simple UI endpoints ---
@app.route("/status", methods=["GET"])
def status():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip, updated_at FROM ip_current WHERE id = 1")
    row = cur.fetchone()
    if not row:
        return jsonify({"status":"no-ip"}), 200
    # last check
    cur.execute("SELECT time, reachable, method, detail FROM checks ORDER BY time DESC LIMIT 1")
    last = cur.fetchone()
    return jsonify({
        "current_ip": row["ip"],
        "ip_updated_at": row["updated_at"],
        "last_check": dict(last) if last else None
    })

@app.route("/history", methods=["GET"])
def history():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT time, ip, reachable, method, detail FROM checks ORDER BY time DESC LIMIT 200")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)

# --- Check functions ---
def ping_icmp(ip, timeout=2):
    try:
        # use system ping: cross-platform? on Linux
        res = subprocess.run(["ping", "-c", "2", "-W", str(timeout), ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ok = res.returncode == 0
        detail = res.stdout.decode(errors="ignore")[:2000]
        return ok, detail
    except Exception as e:
        return False, str(e)

def tcp_connect(ip, port=80, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True, f"tcp:{port} ok"
    except Exception as e:
        return False, str(e)

def http_get(ip, path=HTTP_CHECK_PATH, timeout=5):
    url = f"http://{ip}{path}"
    try:
        r = requests.get(url, timeout=timeout)
        return (r.status_code == 200), f"status:{r.status_code}"
    except Exception as e:
        return False, str(e)

def do_check():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute("SELECT ip FROM ip_current WHERE id = 1")
    row = cur.fetchone()
    if not row:
        db.close()
        return
    ip = row[0]
    ts = datetime.utcnow()
    # 1) ICMP
    ok, detail = ping_icmp(ip)
    cur.execute("INSERT INTO checks (ip, time, reachable, method, detail) VALUES (?, ?, ?, ?, ?)", (ip, ts, int(ok), "icmp", detail[:2000]))
    # 2) TCP 80 and 443
    for port in (80, 443):
        ok2, d2 = tcp_connect(ip, port=port)
        cur.execute("INSERT INTO checks (ip, time, reachable, method, detail) VALUES (?, ?, ?, ?, ?)", (ip, ts, int(ok2), f"tcp:{port}", d2[:2000]))
    # 3) HTTP health (if desired)
    ok3, d3 = http_get(ip)
    cur.execute("INSERT INTO checks (ip, time, reachable, method, detail) VALUES (?, ?, ?, ?, ?)", (ip, ts, int(ok3), "http", d3[:2000]))
    db.commit()
    db.close()

# --- Scheduler setup ---
scheduler = BackgroundScheduler()
scheduler.add_job(func=do_check, trigger="interval", seconds=CHECK_INTERVAL_SECONDS)
scheduler.start()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
