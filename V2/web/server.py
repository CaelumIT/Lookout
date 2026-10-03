#!/usr/bin/env python3
"""
Lookout web server: serves the UI and exposes a small JSON API over the configured data
sources and your local Ollama. Standard library only (plus a database driver if you use one).

    python3 web/server.py --config lookout.toml
"""
import argparse
import datetime
import json
import os
import sys
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from lookout_core import analysis as A  # noqa: E402
from lookout_core import ioc as IOC  # noqa: E402
from lookout_core.evidence import EvidenceError  # noqa: E402
from lookout_core.federated import Federation, _tag  # noqa: E402
from lookout_core import config as C  # noqa: E402
from lookout_core import prompts as P  # noqa: E402
from lookout_core.models import coerce_record, coerce_relation  # noqa: E402
from lookout_core.ollama import Ollama, OllamaError  # noqa: E402
from lookout_core.sources import SourceError, create_sources  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
MAX_BODY = 8 * 1024 * 1024


class BadRequest(Exception):
    pass


class NotFound(Exception):
    pass


class App:
    """Everything the handlers need. Built once at start-up."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.sources = create_sources(cfg["sources"])
        self.ollama = Ollama(cfg["ollama"]["url"], cfg["ollama"].get("default_model"), int(cfg["ollama"]["timeout"]))
        self._prompts = {}
        self.federation = Federation(self.sources) if len(self.sources) > 1 else None
        self.hashes = {}                    # (source id, record id) -> facts from the last verification

    def source(self, sid, concrete=False):
        if sid == "*":
            if concrete:
                raise BadRequest("Use the record's own data source for this request")
            if not self.federation:
                raise NotFound("Only one data source is configured")
            return self.federation
        if sid not in self.sources:
            raise NotFound(f"Unknown data source: {sid!r}")
        return self.sources[sid]

    def prompts(self, src):
        if src.id not in self._prompts:
            self._prompts[src.id] = P.build(src.info())
        return self._prompts[src.id]

    def llm(self, body):
        return self.ollama.with_model(str(body.get("model") or "") or None)

    # ---- JSON endpoints ----
    def sources_list(self, body):
        infos = [s.info() for s in self.sources.values()]
        if self.federation:
            infos.append(self.federation.info())
        return {"sources": infos, "default_model": self.ollama.model}

    def models(self, body):
        return {"models": self.ollama.models()}

    def test(self, body):
        return {"ok": True, "message": self.source(body.get("source")).test()}

    def search(self, body):
        term = str(body.get("term") or "").strip()
        if not term:
            raise BadRequest("Empty search term")
        limit = max(1, min(int(body.get("limit") or 30), 100))
        filters = A.clean_filters(body.get("filters"))
        src = self.source(body.get("source"))
        if getattr(src, "is_federation", False):
            r = src.search_all(term, limit, filters)
            return {"records": r["records"], "total": r["total"], "errors": r["errors"], "counts": r["counts"]}
        f = {k: v for k, v in filters.items() if k in src.filter_keys}
        records, total = src.search(term, limit, filters=f) if f else src.search(term, limit)
        _tag(records, src)
        return {"records": records, "total": total if total is not None else len(records)}

    def related(self, body):
        rid = str(body.get("id") or "")
        if not rid:
            raise BadRequest("Missing record id")
        return {"items": self.source(body.get("source"), concrete=True).related(rid)}

    def iocs(self, body):
        """Indicators (IPs, domains, hashes, CVEs...) found in a record's text, or in text sent directly."""
        try:
            if body.get("record"):
                r = coerce_record(body["record"])
                text = " ".join([r["name"], r["description"], r.get("code") or "", *r["aliases"], *[m["v"] for m in r["meta"]]])
            else:
                text = str(body.get("text") or "")
        except (ValueError, TypeError, AttributeError) as e:
            raise BadRequest(f"Malformed request: {e}")
        return {"iocs": IOC.extract(text)}

    def evidence(self, body):
        """Verify a file behind a record. The path always comes from the data source, never from the browser."""
        src = self.source(body.get("source"), concrete=True)
        if not src.content:
            raise BadRequest("This data source has no [sources.content] section, so Lookout cannot read its files.")
        rec = src.get(str(body.get("id") or ""))
        ev = (rec or {}).get("evidence") or {}
        if not ev.get("path"):
            raise NotFound("That record has no file path")
        facts = src.content.verify(ev["path"], want_hash=bool(body.get("hash", True)))
        if facts.get("sha256"):
            self.hashes[(src.id, rec["id"])] = facts
        out = {"facts": facts, "index": {k: ev.get(k) for k in ("size", "modified", "indexed", "ai_derived")}}
        try:
            out["size_matches_index"] = ev.get("size") in (None, "") or int(ev["size"]) == facts["size"]
        except (TypeError, ValueError):
            out["size_matches_index"] = None
        if body.get("text"):
            t = src.content.text(ev["path"])
            out["text"] = t
            out["iocs"] = IOC.extract(t["text"]) if t else []
        return out

    # ---- streaming endpoints (generators of events) ----
    def contextual(self, body):
        src = self.source(body.get("source"))
        question = str(body.get("question") or "").strip()
        if not question:
            raise BadRequest("Empty question")
        for ev in A.iter_context(question, src, self.llm(body), self.prompts(src)["plan"]):
            if "context" in ev and not getattr(src, "is_federation", False):
                for g in ev["context"]["groups"]:
                    _tag(g["records"], src)
            yield ev

    def generate(self, body):
        src = self.source(body.get("source"))
        kind = body.get("kind")
        try:
            req = {"term": str(body.get("term") or ""), "total": body.get("total"),
                   "records": [coerce_record(r) for r in (body.get("records") or [])[:100]],
                   "context": A.coerce_context(body["context"]) if body.get("context") else None,
                   "focus": None}
            if body.get("focus"):
                f = body["focus"]
                req["focus"] = {"record": coerce_record(f["record"]), "related": [coerce_relation(x) for x in f.get("related", [])]}
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise BadRequest(f"Malformed request: {e}")
        for r in req["records"] + (A.context_records(req["context"]) if req["context"] else []) + ([req["focus"]["record"]] if req["focus"] else []):
            h = self.hashes.get((r.get("source"), r["id"]))
            if h and r.get("evidence"):                       # hashes the server verified in this session
                r["evidence"].update(sha256=h["sha256"], hashed_at=h["hashed_at"], stable=h["stable"])
        llm = self.llm(body)
        date = datetime.date.today().isoformat()
        messages = num_ctx = None
        used = list(req["records"])
        for ev in A.prepare(kind, req, src.info(), self.prompts(src), src, date):
            if "messages" in ev:
                messages, num_ctx = ev["messages"], ev["num_ctx"]
            elif "used" in ev:
                used = ev["used"]
            else:
                yield ev
        stream = llm.stream(messages, num_ctx=num_ctx)
        try:
            for tok in stream:
                yield {"token": tok}
        finally:
            stream.close()        # closes the Ollama connection if the browser went away
        if kind == "bulletin":
            appendix = A.evidence_appendix(used, self.hashes)
            if appendix:
                yield {"token": appendix}
        yield {"done": True}


class Handler(BaseHTTPRequestHandler):
    app = None
    server_version = "Lookout/2.0"

    def log_message(self, fmt, *a):
        sys.stderr.write("[lookout] " + (fmt % a) + "\n")

    # ---- plumbing ----
    def _send_json(self, status, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self):
        """Only accept requests addressed to localhost, from this page itself."""
        host = self.headers.get("Host") or ""
        hostname = host.split("]")[0] + "]" if host.startswith("[") else host.rsplit(":", 1)[0]
        if hostname not in LOCAL_HOSTS:
            self._send_json(403, {"error": "Host not allowed"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != host:
            self._send_json(403, {"error": "Cross-origin requests are not allowed"})
            return False
        return True

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise BadRequest("Request too large")
        if not n:
            return {}
        try:
            b = json.loads(self.rfile.read(n))
        except ValueError:
            raise BadRequest("Body is not valid JSON")
        if not isinstance(b, dict):
            raise BadRequest("Body must be a JSON object")
        return b

    def _error(self, e):
        if isinstance(e, BadRequest):
            return 400, str(e)
        if isinstance(e, NotFound):
            return 404, str(e)
        if isinstance(e, EvidenceError):
            return 400, str(e)
        if isinstance(e, (SourceError, OllamaError)):
            return 502, str(e)
        sys.stderr.write(traceback.format_exc())
        return 500, "Internal error (see the server log)"

    def _stream(self, gen):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for ev in gen:
                self.wfile.write(json.dumps(ev, ensure_ascii=False).encode() + b"\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass                       # the browser stopped listening (Stop button, new search)
        except Exception as e:
            _, msg = self._error(e)
            try:
                self.wfile.write(json.dumps({"error": msg}).encode() + b"\n")
            except OSError:
                pass
        finally:
            gen.close()
            self.close_connection = True

    # ---- routing ----
    JSON_ROUTES = {"/api/sources": "sources_list", "/api/models": "models", "/api/test": "test",
                   "/api/search": "search", "/api/related": "related",
                   "/api/iocs": "iocs", "/api/evidence": "evidence"}
    STREAM_ROUTES = {"/api/contextual": "contextual", "/api/generate": "generate"}

    def _route(self, method):
        if not self._allowed():
            return
        path = urlparse(self.path).path
        try:
            if method == "GET" and path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif path in self.JSON_ROUTES and (method == "POST" or path in ("/api/sources", "/api/models")):
                self._send_json(200, getattr(self.app, self.JSON_ROUTES[path])(self._body() if method == "POST" else {}))
            elif path in self.STREAM_ROUTES and method == "POST":
                body = self._body()
                gen = getattr(self.app, self.STREAM_ROUTES[path])(body)
                # run up to the first event so validation errors become proper HTTP errors
                first = next(gen, None)
                self._stream(_chain(first, gen))
            else:
                self._send_json(404, {"error": "Not found"})
        except Exception as e:
            status, msg = self._error(e)
            self._send_json(status, {"error": msg})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


def _chain(first, rest):
    try:
        if first is not None:
            yield first
        yield from rest
    finally:
        rest.close()


def main():
    ap = argparse.ArgumentParser(description="Lookout: search your data sources with a local Ollama model")
    ap.add_argument("--config", default=os.environ.get("LOOKOUT_CONFIG", "lookout.toml"))
    ap.add_argument("--port", type=int)
    ap.add_argument("--open", action="store_true", help="open the page in your browser")
    args = ap.parse_args()
    try:
        cfg = C.load(args.config)
        app = App(cfg)
    except (C.ConfigError, SourceError) as e:
        sys.exit(f"Configuration problem: {e}")

    Handler.app = app
    port = args.port or int(cfg["server"].get("port", 8765))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    url = f"http://localhost:{port}"
    print(f"Lookout is running at {url}  ({len(app.sources)} data source(s): {', '.join(app.sources)})  Ctrl+C to stop")
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
