"""QNAP Qsirch adapter (file search on a NAS).

STATUS: the mapping, relationship, filter and evidence logic is complete and tested against sample data.
The one missing piece is HttpBackend, which needs the Qsirch API reference served by the NAS
(http://<NAS>:<port>/qsirch/latest/api). No endpoint or field name is guessed here: until the reference
is available, `backend = "fixture"` develops against sample data and `backend = "http"` reports clearly that
it is waiting for the reference.

What is done and what is waiting:
  done     record mapping from configurable field paths, pivot relations (people, tags, objects, places,
           folder), evidence provenance (path, size, times, which text is AI-derived), filters, capability
           reporting, hashing and text reading through a mounted share (see ../evidence.py)
  waiting  HttpBackend: login, search, get, thumbnails, capability detection, and the default mapping
"""
import json
import os
import re

from ..models import record, relation
from .base import DataSource, SourceError
from .elastic import as_list, dig

API_PENDING = ("The Qsirch HTTP backend is not written yet: it is waiting for the Qsirch API reference from your NAS "
               "(http://<NAS>:<port>/qsirch/latest/api). Set backend = \"fixture\" to work with sample data meanwhile.")

CATEGORY_TYPES = {"document": "Document", "image": "Photo", "photo": "Photo", "picture": "Photo", "video": "Video",
                  "audio": "Audio", "music": "Audio", "email": "Email", "mail": "Email"}
AI_FIELDS = ("ocr", "summary", "transcript", "description_ai", "caption")      # mapping keys holding machine-generated text
PIVOTS = [("people", "Person", "shows"), ("tags", "Tag", "tagged"), ("objects", "Object", "shows"),
          ("places", "Place", "taken at")]


class QsirchBackend:
    """What the adapter needs from Qsirch. Implementations return raw dicts; the mapping turns them into records."""
    applies_filters = False          # True when the backend filters on the server

    def test(self):
        raise NotImplementedError

    def capabilities(self):
        return {}

    def search(self, term, filters, limit):
        raise NotImplementedError

    def get(self, raw_id):
        raise NotImplementedError

    def thumbnail(self, raw_id):
        raise NotImplementedError


class HttpBackend(QsirchBackend):
    """Placeholder. Needs: login (QTS session or token), the search endpoint and its filter parameters,
    a fetch-one endpoint, thumbnail retrieval, and a way to detect semantic search and AI Mode."""

    def __init__(self, cfg):
        self.cfg = cfg

    def test(self):
        raise SourceError(API_PENDING)

    search = get = thumbnail = lambda self, *a, **k: (_ for _ in ()).throw(SourceError(API_PENDING))


class FixtureBackend(QsirchBackend):
    """Reads sample items from a JSON file: {"capabilities": {...}, "items": [{...}, ...]}.
    Search is a plain case-insensitive substring match over every text value."""

    def __init__(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise SourceError(f"Could not read the fixture file {path}: {e}")
        self.items = data.get("items", [])
        self.caps = data.get("capabilities", {})

    def test(self):
        return f"Fixture backend: {len(self.items)} sample item(s). This is sample data, not your NAS."

    def capabilities(self):
        return dict(self.caps)

    @staticmethod
    def _text(v):
        if isinstance(v, dict):
            return " ".join(FixtureBackend._text(x) for x in v.values())
        if isinstance(v, list):
            return " ".join(FixtureBackend._text(x) for x in v)
        return "" if v is None else str(v)

    def search(self, term, filters, limit):
        t = term.lower()
        hits = [i for i in self.items if t in self._text(i).lower()]
        return hits[:limit], len(hits)

    def get(self, raw_id):
        return next((i for i in self.items if str(i.get("id")) == str(raw_id)), None)

    def thumbnail(self, raw_id):
        return None


def _human(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class QsirchSource(DataSource):
    kind = "qsirch"
    filter_keys = ("category", "date_from", "date_to", "path_contains")
    default_examples = []
    default_questions = []

    def __init__(self, cfg, backend=None):
        super().__init__(cfg)
        m = self.m = cfg.get("mapping") or {}
        if not m.get("id") or not (m.get("name") or m.get("path")):
            raise SourceError(f"Source '{self.id}': [sources.mapping] needs 'id' and at least 'name' or 'path'. "
                              "The defaults will be filled in once the Qsirch API reference is available.")
        kind = str(cfg.get("backend", "http")).lower()
        if backend:
            self.backend = backend
        elif kind == "fixture":
            if not cfg.get("fixture"):
                raise SourceError(f"Source '{self.id}': backend = \"fixture\" needs a 'fixture' file path")
            self.backend = FixtureBackend(cfg["fixture"])
        elif kind == "http":
            self.backend = HttpBackend(cfg)
        else:
            raise SourceError(f"Source '{self.id}': backend must be \"http\" or \"fixture\"")
        self.pivot_fields = [(k, t, r) for k, t, r in PIVOTS if m.get(k)]
        self.relationships = bool(self.pivot_fields or m.get("path"))

    def describe(self):
        return "QNAP Qsirch file index (documents, photos, video and audio on a NAS; text from OCR, image descriptions and transcripts is machine-generated)"

    # ---- mapping ----
    def _folder(self, raw):
        path = (as_list(dig(raw, self.m.get("path"))) or [""])[0]
        return os.path.dirname(path.replace("\\", "/")) if path else ""

    def to_record(self, raw):
        m = self.m
        first = lambda key: (as_list(dig(raw, m.get(key))) or [None])[0]
        path = first("path")
        name = first("name") or (os.path.basename(path.replace("\\", "/")) if path else str(first("id")))
        cat = (first("category") or "").lower()
        rtype = m.get("type_map", {}).get(cat) or CATEGORY_TYPES.get(cat) or (cat.title() if cat else "File")
        ai = {k: " ".join(as_list(dig(raw, m.get(k)))) for k in AI_FIELDS if m.get(k)}
        ai = {k: v for k, v in ai.items() if v.strip()}
        snippet = " ".join(as_list(dig(raw, m.get("snippet")))).strip()
        text = snippet or next(iter(ai.values()), "")
        taken, modified = first("taken"), first("modified")
        meta = [("Size", _human(first("size"))), ("Folder", self._folder(raw))]
        meta += [(label, ", ".join(as_list(dig(raw, p))[:5])) for label, p in (m.get("meta") or {}).items()]
        labels = as_list(dig(raw, m.get("tags"))) + as_list(dig(raw, m.get("objects")))
        ev = {"path": path, "size": first("size"), "modified": modified, "indexed": first("indexed"), "ai_derived": sorted(ai)}
        return record(first("id"), rtype, name, description=text[:1200], labels=labels, meta=meta,
                      date=taken or modified, date_label="Taken" if taken else "Modified", evidence=ev)

    # ---- filters ----
    def _post_filter(self, recs, f):
        out = []
        for r in recs:
            ev = r.get("evidence") or {}
            if f.get("category") and f["category"].lower() not in (r["type"].lower(), r["type"].lower() + "s"):
                continue
            if f.get("path_contains") and f["path_contains"].lower() not in (ev.get("path") or "").lower():
                continue
            d = r.get("date") or ""
            if f.get("date_from") and d < f["date_from"] or f.get("date_to") and d > f["date_to"]:
                continue
            out.append(r)
        return out

    # ---- DataSource ----
    def test(self):
        msg = self.backend.test()
        caps = self.backend.capabilities()
        flags = [k for k, v in caps.items() if v]
        return msg + (f" Capabilities: {', '.join(flags)}." if flags else "")

    def search(self, term, limit=30, filters=None):
        f = {k: v for k, v in (filters or {}).items() if k in self.filter_keys and v}
        raws, total = self.backend.search(term, f, limit if self.backend.applies_filters else limit * 3 if f else limit)
        recs = [self.to_record(r) for r in raws]
        if f and not self.backend.applies_filters:
            recs = self._post_filter(recs, f)
            total = len(recs)
        return recs[:limit], total

    def get(self, record_id):
        raw = self.backend.get(record_id)
        return self.to_record(raw) if raw else None

    def related(self, record_id, limit=80):
        raw = self.backend.get(record_id)
        if not raw:
            return []
        items, seen = [], set()
        for key, rtype, rel in self.pivot_fields:
            for v in as_list(dig(raw, self.m.get(key))):
                if (rtype, v) not in seen:
                    seen.add((rtype, v))
                    items.append(relation(rtype, v, rel))
        folder = self._folder(raw)
        if folder and ("Folder", folder) not in seen:
            items.append(relation("Folder", folder, "stored in"))
        return items[:limit]

    def thumbnail(self, record_id):
        return self.backend.thumbnail(record_id)
