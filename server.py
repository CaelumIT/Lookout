#!/usr/bin/env python3
"""
Lookout relay: serves the UI and forwards requests to OpenCTI and Ollama.

Why it exists: browsers block a web page from calling OpenCTI/Ollama directly
(CORS). This relay runs on your machine, so the page only ever talks to
http://localhost:<port>. It uses the Python standard library only.

    python3 server.py                 # http://localhost:8765
    python3 server.py --port 9000
    python3 server.py --insecure      # accept self-signed TLS certs on OpenCTI
"""
import argparse
import os
import ssl
import sys
import json
import webbrowser
import urllib.request
import urllib.error
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
SSL_CTX = None


def hostname_of(host_header: str) -> str:
    if host_header.startswith("["):
        return host_header.split("]")[0] + "]"
    return host_header.rsplit(":", 1)[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "Lookout/1.0"

    def log_message(self, fmt, *a):
        sys.stderr.write("[lookout] " + (fmt % a) + "\n")

    # -- helpers ---------------------------------------------------------
    def _json(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self):
        """Only accept requests addressed to localhost, from this page itself."""
        host = self.headers.get("Host") or ""
        if hostname_of(host) not in LOCAL_HOSTS:
            self._json(403, {"error": "Host not allowed"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != host:
            self._json(403, {"error": "Cross-origin requests are not allowed"})
            return False
        return True

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if not self._allowed():
            return
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/proxy":
            self._proxy()
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._allowed():
            return
        if urlparse(self.path).path == "/proxy":
            self._proxy()
        else:
            self._json(404, {"error": "Not found"})

    def _proxy(self):
        target = self.headers.get("X-Target-Url") or ""
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self._json(400, {"error": "Missing or invalid X-Target-Url"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(target, data=body, method=self.command)
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
        if self.headers.get("X-Target-Auth"):
            req.add_header("Authorization", self.headers["X-Target-Auth"])
        req.add_header("Accept", "application/json, application/x-ndjson")

        try:
            resp = urllib.request.urlopen(req, timeout=600, context=SSL_CTX)
            status = resp.status
        except urllib.error.HTTPError as e:  # upstream answered with an error code
            resp, status = e, e.code
        except Exception as e:  # could not connect at all
            reason = getattr(e, "reason", e)
            self._json(502, {"error": f"Could not reach {parsed.netloc}: {reason}"})
            return

        self.send_response(status)
        self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            while True:
                chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()  # lets Ollama tokens stream through live
        except (BrokenPipeError, ConnectionResetError):
            pass  # the browser stopped listening (e.g. Stop button)
        finally:
            resp.close()
        self.close_connection = True


def main():
    global SSL_CTX
    ap = argparse.ArgumentParser(description="Lookout: OpenCTI search with local Ollama recommendations")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate checks for upstream servers")
    ap.add_argument("--open", action="store_true", help="open the page in your browser")
    args = ap.parse_args()

    if args.insecure:
        SSL_CTX = ssl.create_default_context()
        SSL_CTX.check_hostname = False
        SSL_CTX.verify_mode = ssl.CERT_NONE

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    httpd.daemon_threads = True
    url = f"http://localhost:{args.port}"
    print(f"Lookout is running at {url}  (Ctrl+C to stop)")
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
