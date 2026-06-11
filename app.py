#!/usr/bin/env python3
"""
Deception Engine - Central Console (SAFE VERSION)
Runs inside Docker, uses SQLite inside container (no host access)
"""

from flask import Flask, render_template, request, jsonify, Response
import sqlite3
import json
import time
from datetime import datetime
import threading

app = Flask(__name__)

# Database inside container only
DATABASE = "/app/data/attacks.db"
import os
os.makedirs("/app/data", exist_ok=True)

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT,
            timestamp TEXT,
            service TEXT,
            source_ip TEXT,
            source_port INTEGER,
            attack_type TEXT,
            data TEXT,
            raw_length INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

attack_queue = []
queue_lock = threading.Lock()

@app.route("/api/attack", methods=["POST"])
def receive_attack():
    """Receive attack data from honeypot nodes."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO attacks (node_id, timestamp, service, source_ip, 
                             source_port, attack_type, data, raw_length)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("node_id"),
        data.get("timestamp"),
        data.get("service"),
        data.get("source_ip"),
        data.get("source_port"),
        data.get("attack_type"),
        data.get("data"),
        data.get("raw_length", 0)
    ))
    conn.commit()
    conn.close()
    
    with queue_lock:
        attack_queue.append(data)
    
    return jsonify({"status": "logged"}), 201


@app.route("/api/stats")
def get_stats():
    """Return aggregated statistics."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) as total FROM attacks")
    total = c.fetchone()["total"]
    
    c.execute("SELECT service, COUNT(*) as count FROM attacks GROUP BY service ORDER BY count DESC")
    by_service = {row["service"]: row["count"] for row in c.fetchall()}
    
    c.execute("SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type ORDER BY count DESC")
    by_type = {row["attack_type"]: row["count"] for row in c.fetchall()}
    
    c.execute("""
        SELECT source_ip, COUNT(*) as count, GROUP_CONCAT(DISTINCT service) as services 
        FROM attacks GROUP BY source_ip ORDER BY count DESC LIMIT 20
    """)
    top_ips = [dict(row) for row in c.fetchall()]
    
    c.execute("""SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50""")
    recent = [dict(row) for row in c.fetchall()]
    
    c.execute("""SELECT COUNT(*) as count FROM attacks WHERE timestamp >= datetime('now', '-1 day')""")
    last_24h = c.fetchone()["count"]
    
    c.execute("SELECT COUNT(DISTINCT source_ip) as count FROM attacks")
    unique_ips = c.fetchone()["count"]
    
    conn.close()
    
    return jsonify({
        "total": total,
        "last_24h": last_24h,
        "unique_ips": unique_ips,
        "by_service": by_service,
        "by_type": by_type,
        "top_ips": top_ips,
        "recent": recent
    })


@app.route("/api/stream")
def stream_attacks():
    """SSE endpoint for real-time attack streaming."""
    def generate():
        while True:
            with queue_lock:
                while attack_queue:
                    data = attack_queue.pop(0)
                    yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)
            yield ": heartbeat\n\n"
    
    return Response(generate(), mimetype="text/event-stream")


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/export")
def export_data():
    """Export all attack data as JSON."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM attacks ORDER BY timestamp DESC")
    attacks = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({"exported_at": datetime.utcnow().isoformat(), "attacks": attacks})


if __name__ == "__main__":
    print("Deception Engine Console starting on :5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
