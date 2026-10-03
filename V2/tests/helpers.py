import json
import os
import sqlite3
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def make_sqlite():
    path = os.path.join(tempfile.mkdtemp(), "sec.db")
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE incidents(id INTEGER PRIMARY KEY, title TEXT, summary TEXT, notes TEXT, status TEXT, severity TEXT,
                           created_at TEXT, tags TEXT, aliases TEXT);
    CREATE TABLE assets(id INTEGER PRIMARY KEY, hostname TEXT, owner TEXT);
    CREATE TABLE incident_assets(incident_id INTEGER, asset_id INTEGER);
    INSERT INTO incidents VALUES (1,'Ransomware on FIN-01','Encrypted file shares','50% of volumes hit','open','high','2026-09-01 10:00:00','ransomware;finance','BlackCat Hit');
    INSERT INTO incidents VALUES (2,'Phishing campaign','Credential harvesting emails','', 'closed','medium','2026-08-15 09:00:00','phishing','');
    INSERT INTO incidents VALUES (3,'Odd_name% test','wildcards','', 'open','low','2026-07-01 00:00:00','','');
    INSERT INTO assets VALUES (1,'FIN-01','finance'),(2,'HR-02','hr');
    INSERT INTO incident_assets VALUES (1,1),(2,1),(2,2);
    """)
    db.commit()
    db.close()
    return path


def sql_cfg(path, **extra):
    return {
        "id": "secdb", "kind": "sqlite", "label": "Security DB", "path": path,
        "entities": [{"table": "incidents", "type": "Incident", "id": "id", "name": "title", "description": "summary",
                      "aliases": "aliases", "labels": "tags", "date": "created_at",
                      "search": ["title", "summary", "notes"], "meta": {"Status": "status", "Severity": "severity"}},
                     {"table": "assets", "type": "Asset", "id": "id", "name": "hostname", "description": "owner"}],
        "relations": [{"entity": "Incident", "rel": "affects", "type": "Asset",
                       "sql": "SELECT a.hostname AS name FROM incident_assets ia JOIN assets a ON a.id = ia.asset_id WHERE ia.incident_id = :id"}],
        **extra,
    }


class MockHTTP:
    """A tiny HTTP server for tests. handler(method, path, headers, body) -> (status, obj_or_list_of_lines)."""

    def __init__(self, handler):
        outer = self
        self.requests = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                body = json.loads(raw) if raw else None
                outer.requests.append((self.command, self.path, dict(self.headers), body))
                status, out = handler(self.command, self.path, dict(self.headers), body)
                self.send_response(status)
                if isinstance(out, list):
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.end_headers()
                    for line in out:
                        self.wfile.write((json.dumps(line) + "\n").encode())
                        self.wfile.flush()
                else:
                    data = json.dumps(out).encode()
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

            do_GET = do_POST = _do

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
