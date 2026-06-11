#!/usr/bin/env python3
"""
Deception Engine - Honeypot Node
SAFE VERSION - Runs inside Docker, isolated from host
"""

import socket
import threading
import json
import time
import logging
import os
import uuid
import requests
from datetime import datetime

# ===== CONFIGURATION =====
CENTRAL_CONSOLE_URL = os.environ.get("CONSOLE_URL", "http://console:5000/api/attack")
NODE_ID = os.environ.get("NODE_ID", str(uuid.uuid4())[:8])
HOST = "0.0.0.0"

# Only these ports - we're not binding to privileged ports inside Docker
# Docker will map external ports to these internal ones
SERVICES = {
    2222: ("ssh", "SSH Server"),
    8080: ("http", "HTTP Server"),
    2121: ("ftp", "FTP Server"),
    3307: ("mysql", "MySQL Database"),
    4450: ("smb", "SMB File Share"),
}

# ===== LOGGING SETUP =====
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()  # Only stdout inside container
    ]
)
logger = logging.getLogger(__name__)


def log_attack(service, source_ip, source_port, data, attack_type="connection"):
    """Log an attack locally and send to central console."""
    timestamp = datetime.utcnow().isoformat()
    attack = {
        "node_id": NODE_ID,
        "timestamp": timestamp,
        "service": service,
        "source_ip": source_ip,
        "source_port": source_port,
        "attack_type": attack_type,
        "data": data[:1024].decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)[:1024],
        "raw_length": len(data) if isinstance(data, bytes) else len(str(data)),
    }
    
    logger.warning(f"[{service}] Attack from {source_ip}:{source_port} - {attack_type}")
    
    try:
        requests.post(CENTRAL_CONSOLE_URL, json=attack, timeout=2)
    except Exception as e:
        logger.warning(f"Console unreachable: {e}")
    
    return attack


def handle_ssh(conn, addr):
    """Emulate SSH server."""
    ip, port = addr
    conn.settimeout(30)
    conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    
    buffer = b""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data
            conn.send(b"Permission denied (publickey,password).\r\n")
    except socket.timeout:
        pass
    except:
        pass
    finally:
        if buffer:
            log_attack("ssh", ip, port, buffer, "interaction")
        conn.close()


def handle_http(conn, addr):
    """Emulate HTTP server with login page."""
    ip, port = addr
    conn.settimeout(15)
    
    try:
        data = conn.recv(8192)
        if not data:
            conn.close()
            return
            
        # Classify attack
        attack_type = "http_request"
        decoded = data.decode("utf-8", errors="ignore").lower()
        if any(x in decoded for x in ["sql", "union", "select", "from", "where"]):
            attack_type = "sql_injection"
        elif any(x in decoded for x in ["<script", "alert(", "onerror"]):
            attack_type = "xss_attempt"
        elif any(x in decoded for x in ["../", "..%2f", "..\\"]):
            attack_type = "path_traversal"
        elif "admin" in decoded:
            attack_type = "admin_bruteforce"
        elif "post" in decoded:
            attack_type = "form_submission"
            
        log_attack("http", ip, port, data, attack_type)
        
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"<html><body><h1>Employee Portal</h1>"
            b"<form method='POST'><input name='user'><input name='pass' type='password'>"
            b"<input type='submit'></form></body></html>"
        )
        conn.send(response)
    except:
        pass
    finally:
        conn.close()


def handle_ftp(conn, addr):
    """Emulate FTP server."""
    ip, port = addr
    conn.settimeout(30)
    conn.send(b"220 ProFTPD 1.3.5 Server ready.\r\n")
    
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            cmd = data.decode("utf-8", errors="ignore").strip().upper()
            if cmd.startswith("USER"):
                log_attack("ftp", ip, port, data, "username_attempt")
                conn.send(b"331 Password required.\r\n")
            elif cmd.startswith("PASS"):
                log_attack("ftp", ip, port, data, "password_attempt")
                conn.send(b"530 Login incorrect.\r\n")
            elif cmd == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break
            else:
                conn.send(b"500 Unknown command.\r\n")
    except:
        pass
    finally:
        conn.close()


def handle_mysql(conn, addr):
    """Emulate MySQL server handshake."""
    ip, port = addr
    conn.settimeout(15)
    
    try:
        conn.send(b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00")
        data = conn.recv(4096)
        if data:
            log_attack("mysql", ip, port, data, "connection_attempt")
    except:
        pass
    finally:
        conn.close()


def handle_smb(conn, addr):
    """Log SMB connections."""
    ip, port = addr
    conn.settimeout(15)
    try:
        data = conn.recv(4096)
        if data:
            log_attack("smb", ip, port, data, "smb_connection")
    except:
        pass
    finally:
        conn.close()


HANDLERS = {
    "ssh": handle_ssh,
    "http": handle_http,
    "ftp": handle_ftp,
    "mysql": handle_mysql,
    "smb": handle_smb,
}


running = True

def start_service(port, service_name):
    """Start a single honeypot service."""
    handler = HANDLERS.get(service_name)
    if not handler:
        return
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1)
    
    try:
        server.bind((HOST, port))
        server.listen(5)
        logger.info(f"[+] {service_name.upper()} on :{port}")
    except Exception as e:
        logger.error(f"[-] {service_name}:{port} - {e}")
        return
    
    while running:
        try:
            conn, addr = server.accept()
            thread = threading.Thread(target=handler, args=(conn, addr), daemon=True)
            thread.start()
        except socket.timeout:
            continue
        except:
            break
    
    server.close()


if __name__ == "__main__":
    logger.info(f"Starting Honeypot Node: {NODE_ID}")
    logger.info(f"Console URL: {CENTRAL_CONSOLE_URL}")
    
    threads = []
    for port, (svc, name) in SERVICES.items():
        t = threading.Thread(target=start_service, args=(port, svc), daemon=True)
        t.start()
        threads.append(t)
    
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        running = False
