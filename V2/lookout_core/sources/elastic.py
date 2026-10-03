"""Elasticsearch / OpenSearch adapter (HTTP + JSON, standard library only).

Documents become records through a field mapping in the config. Documents have no built-in
relationships, so "related" means the values of configured pivot fields (hosts, users, IPs...).
Clicking one searches for it, which finds the other documents that mention it."""
import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from ..models import record, relation
from .base import DataSource, SourceError

NAME_FALLBACKS = ["name", "title", "message", "rule.name", "event.action"]


def dig(src, path):
    """Read a dotted path from a document, accepting both flattened keys and nested objects."""
    if not path:
        return None
    if path in src:
        return src[path]
    cur = src
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def as_list(v):
    if v is None:
        return []
    out = []
    for x in (v if isinstance(v, list) else [v]):
        if isinstance(x, (dict, list)):
            continue
        s = str(x).strip()
        if s:
            out.append(s)
    return out


class ElasticSource(DataSource):
    kind = "elasticsearch"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.url = str(cfg.get("url") or "").rstrip("/")
        if not self.url:
            raise SourceError(f"Source '{self.id}': 'url' is required")
        self.index = str(cfg.get("index") or "*")
        self.timeout = int(cfg.get("timeout", 30))
        m = cfg.get("mapping") or {}
        self.m = m
        self.search_fields = m.get("search_fields") or ["*"]
        self.pivots = {k: ([v] if isinstance(v, str) else list(v)) for k, v in (m.get("pivots") or {}).items()}
        self.pivot_rel = m.get("pivot_rel", "mentions")
        self.relationships = bool(self.pivots)
        self.headers = {"Content-Type": "application/json"}
        if cfg.get("api_key"):
            self.headers["Authorization"] = "ApiKey " + str(cfg["api_key"])
        elif cfg.get("username"):
            token = base64.b64encode(f"{cfg['username']}:{cfg.get('password', '')}".encode()).decode()
            self.headers["Authorization"] = "Basic " + token
        self.ctx = None
        if str(cfg.get("url", "")).startswith("https"):
            if cfg.get("ca_file"):
                try:
                    self.ctx = ssl.create_default_context(cafile=cfg["ca_file"])
                except (OSError, ssl.SSLError) as e:
                    raise SourceError(f"Source '{self.id}': cannot use ca_file {cfg['ca_file']!r} ({e.strerror or e})")
            elif not cfg.get("verify_tls", True):
                self.ctx = ssl._create_unverified_context()

    def describe(self):
        return f"{self.kind.capitalize()} index pattern '{self.index}' (documents such as logs or events)"

    # ---- HTTP ----
    def _http(self, method, path, body=None):
        req = urllib.request.Request(self.url + path, method=method, headers=self.headers,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404 and "/_doc/" in path:
                return None
            reason = ""
            try:
                err = json.loads(e.read()).get("error", {})
                reason = err.get("reason") or (err.get("root_cause") or [{}])[0].get("reason") or str(err)
            except (ValueError, AttributeError):
                pass
            if e.code in (401, 403):
                raise SourceError(f"The search server rejected the credentials (HTTP {e.code}) {reason}".strip())
            raise SourceError(f"The search server answered HTTP {e.code}: {reason}".strip())
        except urllib.error.URLError as e:
            raise SourceError(f"Could not reach {self.url}: {e.reason}")
        except OSError as e:
            raise SourceError(f"The search server did not answer in time: {e}")

    def _index_path(self):
        return urllib.parse.quote(self.index, safe=",*-_.")

    def _includes(self):
        m = self.m
        paths = [m.get(k) for k in ("name", "description", "date", "type", "aliases", "labels", "code")]
        paths += list((m.get("meta") or {}).values()) + [p for ps in self.pivots.values() for p in ps]
        paths += [] if m.get("name") else NAME_FALLBACKS
        return sorted({p for p in paths if p})

    # ---- mapping ----
    def _to_record(self, index, doc_id, src):
        m = self.m
        name = next((as_list(dig(src, p))[0] for p in [m.get("name")] + NAME_FALLBACKS if p and as_list(dig(src, p))), doc_id)
        desc = " ".join(as_list(dig(src, m.get("description"))))
        meta = [(label, ", ".join(as_list(dig(src, path))[:5])) for label, path in (m.get("meta") or {}).items()]
        rtype = (as_list(dig(src, m.get("type"))) or [m.get("type_value", "Document")])[0]
        date = (as_list(dig(src, m.get("date"))) or [None])[0]
        code = (as_list(dig(src, m.get("code"))) or [None])[0]
        return record(f"{index}|{doc_id}", rtype, name, description=desc, aliases=as_list(dig(src, m.get("aliases"))),
                      labels=as_list(dig(src, m.get("labels"))), meta=meta, code=code, date=date, date_label="Time")

    # ---- DataSource ----
    def test(self):
        r = self._http("POST", f"/{self._index_path()}/_count", {"query": {"match_all": {}}})
        return f"Connected; {r.get('count', 0):,} documents in '{self.index}'"

    def search(self, term, limit=30, filters=None):
        body = {"size": int(limit), "track_total_hits": True,
                "query": {"simple_query_string": {"query": term, "fields": self.search_fields,
                                                  "default_operator": "and", "lenient": True}}}
        inc = self._includes()
        if inc:
            body["_source"] = {"includes": inc}
        res = self._http("POST", f"/{self._index_path()}/_search", body)
        hits = (res.get("hits") or {}).get("hits", [])
        total = (res.get("hits") or {}).get("total")
        total = total.get("value") if isinstance(total, dict) else total
        return [self._to_record(h["_index"], h["_id"], h.get("_source") or {}) for h in hits], total

    def _fetch(self, record_id):
        if "|" not in record_id:
            return None
        index, doc_id = record_id.split("|", 1)
        res = self._http("GET", f"/{urllib.parse.quote(index, safe='')}/_doc/{urllib.parse.quote(doc_id, safe='')}")
        return (index, doc_id, res.get("_source") or {}) if res and res.get("found", True) else None

    def get(self, record_id):
        doc = self._fetch(record_id)
        return self._to_record(*doc) if doc else None

    def related(self, record_id, limit=80):
        if not self.pivots:
            return []
        doc = self._fetch(record_id)
        if not doc:
            return []
        seen, items = set(), []
        for rtype, paths in self.pivots.items():
            for path in paths:
                for v in as_list(dig(doc[2], path)):
                    if (rtype, v) not in seen and len(items) < limit:
                        seen.add((rtype, v))
                        items.append(relation(rtype, v[:200], self.pivot_rel, "outbound"))
        return items
