"""SQL adapter for MySQL, MariaDB, PostgreSQL and SQLite.

You describe your tables in the config; Lookout builds parameterised, read-only SELECTs.
Relationships come from SELECT statements you write (with a :id placeholder), because only
you know which join tables mean what.

Drivers (not bundled): PyMySQL for mysql/mariadb, psycopg for postgres. sqlite3 is in Python."""
import re
from pathlib import Path
from urllib.parse import quote

from ..models import record, relation
from .base import DataSource, SourceError

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
READONLY_SQL = re.compile(r"^\s*(select|with)\b", re.I)
SPLIT = re.compile(r"[;,|]")


def _ident(src_id, d, key, required=False, default=None):
    v = d.get(key, default)
    if v in (None, ""):
        if required:
            raise SourceError(f"Source '{src_id}': '{key}' is required")
        return None
    if not IDENT.match(str(v)):
        raise SourceError(f"Source '{src_id}': {key} = {v!r} is not a plain table or column name")
    return str(v)


class _Entity:
    def __init__(self, src_id, d):
        self.table = _ident(src_id, d, "table", True)
        self.type = str(d.get("type") or self.table)
        self.id = _ident(src_id, d, "id", True)
        self.name = _ident(src_id, d, "name", True)
        self.description = _ident(src_id, d, "description")
        self.aliases = _ident(src_id, d, "aliases")
        self.labels = _ident(src_id, d, "labels")
        self.date = _ident(src_id, d, "date")
        self.code = _ident(src_id, d, "code")
        self.search = [_ident(src_id, {"c": c}, "c", True) for c in (d.get("search") or [self.name])]
        self.meta = [(str(k), _ident(src_id, {"c": c}, "c", True)) for k, c in (d.get("meta") or {}).items()]
        self.mode = str(d.get("search_mode", "like")).lower()
        if self.mode not in ("like", "fulltext"):
            raise SourceError(f"Source '{src_id}': search_mode must be 'like' or 'fulltext'")


class _Relation:
    def __init__(self, src_id, d):
        self.entity = str(d.get("entity") or "")
        self.sql = str(d.get("sql") or "").strip()
        if not self.entity or not self.sql:
            raise SourceError(f"Source '{src_id}': each [[relations]] needs 'entity' and 'sql'")
        body = self.sql.rstrip().rstrip(";")
        if not READONLY_SQL.match(body) or ";" in body:
            raise SourceError(f"Source '{src_id}': relation SQL must be a single SELECT (or WITH ... SELECT) statement")
        self.type = d.get("type")
        self.rel = d.get("rel", "related-to")
        self.direction = d.get("direction", "outbound")
        self.sql = body


def _pk(value):
    """Record ids carry the key as text; turn plain integers back into integers for the query."""
    return int(value) if re.fullmatch(r"-?[1-9]\d*|0", value) else value


class SQLSource(DataSource):
    relationships = False

    def __init__(self, cfg):
        super().__init__(cfg)
        self.kind = str(cfg["kind"]).lower()
        self.cfg = cfg
        self.entities = [_Entity(self.id, e) for e in cfg.get("entities") or []]
        if not self.entities:
            raise SourceError(f"Source '{self.id}': define at least one [[sources.entities]] table")
        self.relations = [_Relation(self.id, r) for r in cfg.get("relations") or []]
        self.relationships = bool(self.relations)
        self.max_rows = int(cfg.get("max_rows", 100))
        self._ph = "?" if self.kind == "sqlite" else "%s"
        self._by_table = {e.table: e for e in self.entities}
        if self.kind == "sqlite" and not cfg.get("path"):
            raise SourceError(f"Source '{self.id}': sqlite needs 'path'")

    def describe(self):
        tables = ", ".join(f"{e.table} ({e.type})" for e in self.entities)
        return f"{self.kind} relational database; searchable tables: {tables}"

    # ---- connection ----
    def _connect(self):
        c = self.cfg
        try:
            if self.kind == "sqlite":
                import sqlite3
                uri = "file:" + quote(str(Path(c["path"]).resolve())) + "?mode=ro"
                return sqlite3.connect(uri, uri=True, timeout=10)
            if self.kind in ("mysql", "mariadb"):
                import pymysql
                conn = pymysql.connect(host=c.get("host", "localhost"), port=int(c.get("port", 3306)), user=c.get("user"),
                                       password=c.get("password", ""), database=c.get("database"), charset="utf8mb4",
                                       connect_timeout=int(c.get("connect_timeout", 5)), read_timeout=int(c.get("read_timeout", 30)),
                                       ssl_ca=c.get("ssl_ca"))
                try:
                    with conn.cursor() as cur:
                        cur.execute("SET SESSION TRANSACTION READ ONLY")
                except Exception:
                    pass  # old servers; the account should be read-only anyway
                return conn
            if self.kind == "postgres":
                import psycopg
                conn = psycopg.connect(host=c.get("host", "localhost"), port=int(c.get("port", 5432)), user=c.get("user"),
                                       password=c.get("password", ""), dbname=c.get("database"),
                                       connect_timeout=int(c.get("connect_timeout", 5)), options="-c default_transaction_read_only=on")
                return conn
        except ImportError as e:
            hint = {"mysql": "pip install pymysql", "mariadb": "pip install pymysql", "postgres": "pip install 'psycopg[binary]'"}.get(self.kind, "")
            raise SourceError(f"The Python driver for {self.kind} is not installed ({e.name}). Install it with: {hint}")
        except Exception as e:
            raise SourceError(f"Could not connect to the {self.kind} database: {e}")
        raise SourceError(f"Unsupported SQL kind: {self.kind}")

    def _run(self, sql, params=()):
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(sql, tuple(params))
            cols = [d[0].lower() for d in cur.description or []]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        except SourceError:
            raise
        except Exception as e:
            raise SourceError(f"The database rejected a query: {e}")
        finally:
            conn.close()

    # ---- SQL building (pure, unit-tested per dialect) ----
    def _q(self, ident):
        # Backticks for sqlite too: sqlite treats an unknown "double-quoted" name as a string literal,
        # which would turn a typo in the config into silently wrong results instead of an error.
        q = '"' if self.kind == "postgres" else "`"
        return ".".join(f"{q}{p}{q}" for p in ident.split("."))

    def _select(self, e):
        cols = [(e.id, "c_id"), (e.name, "c_name"), (e.description, "c_desc"), (e.aliases, "c_alias"),
                (e.labels, "c_labels"), (e.date, "c_date"), (e.code, "c_code")]
        cols += [(c, f"m_{i}") for i, (_, c) in enumerate(e.meta)]
        return ", ".join(f"{self._q(c)} AS {a}" for c, a in cols if c)

    def build_search(self, e, term, limit):
        q, ph, n = self._q, self._ph, int(limit)
        if e.mode == "fulltext":
            if self.kind not in ("mysql", "mariadb"):
                raise SourceError(f"Source '{self.id}': search_mode 'fulltext' is only available for mysql and mariadb")
            match = f"MATCH({', '.join(q(c) for c in e.search)}) AGAINST ({ph} IN NATURAL LANGUAGE MODE)"
            return f"SELECT {self._select(e)} FROM {q(e.table)} WHERE {match} ORDER BY {match} DESC LIMIT {n}", [term, term]
        op = "ILIKE" if self.kind == "postgres" else "LIKE"
        pat = "%" + term.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        where = " OR ".join(f"{q(c)} {op} {ph} ESCAPE '!'" for c in e.search)
        sql = (f"SELECT {self._select(e)} FROM {q(e.table)} WHERE ({where}) "
               f"ORDER BY CASE WHEN {q(e.name)} = {ph} THEN 0 ELSE 1 END LIMIT {n}")
        return sql, [pat] * len(e.search) + [term]

    def build_get(self, e, pk):
        return f"SELECT {self._select(e)} FROM {self._q(e.table)} WHERE {self._q(e.id)} = {self._ph} LIMIT 1", [_pk(pk)]

    def bind_relation(self, sql, pk):
        if self.kind != "sqlite":
            sql = sql.replace("%", "%%")      # a literal % must be escaped for %s-style drivers
        n = len(re.findall(r":id\b", sql))
        return re.sub(r":id\b", self._ph, sql), [_pk(pk)] * n

    # ---- rows to records ----
    def _to_record(self, e, row):
        split = lambda v: [x.strip() for x in SPLIT.split(str(v))] if v not in (None, "") else []
        meta = [(label, row.get(f"m_{i}")) for i, (label, _) in enumerate(e.meta)]
        return record(f"{e.table}:{row['c_id']}", e.type, row.get("c_name"), description=row.get("c_desc"),
                      aliases=split(row.get("c_alias")), labels=split(row.get("c_labels")), meta=meta,
                      code=row.get("c_code"), date=row.get("c_date"), date_label="Date")

    # ---- DataSource ----
    def test(self):
        for e in self.entities:   # proves the connection, the tables and every mapped column
            self._run(*self.build_search(e, "x", 1))
        for r in self.relations:  # proves each relation query runs (id 0 normally matches nothing)
            self._run(*self.bind_relation(r.sql, "0"))
        return f"Connected; {len(self.entities)} table(s) and {len(self.relations)} relation query(ies) check out"

    def search(self, term, limit=30, filters=None):
        out = []
        for e in self.entities:
            sql, params = self.build_search(e, term, min(int(limit), self.max_rows))
            out += [self._to_record(e, row) for row in self._run(sql, params)]
        out = sorted(out, key=lambda r: (r["name"].lower() != term.lower()))[:limit]   # exact name matches first
        return out, len(out)

    def get(self, record_id):
        table, _, pk = record_id.partition(":")
        e = self._by_table.get(table)
        if not e or not pk:
            return None
        rows = self._run(*self.build_get(e, pk))
        return self._to_record(e, rows[0]) if rows else None

    def related(self, record_id, limit=80):
        table, _, pk = record_id.partition(":")
        e = self._by_table.get(table)
        if not e or not pk:
            return []
        items, seen = [], set()
        for r in self.relations:
            if r.entity not in (e.type, e.table):
                continue
            for row in self._run(*self.bind_relation(r.sql, pk)):
                name = row.get("name")
                if name in (None, ""):
                    continue
                rel = relation(row.get("type") or r.type or "Record", name, row.get("rel") or r.rel,
                               row.get("dir") or r.direction, row.get("code"))
                key = (rel["type"], rel["name"], rel["rel"], rel["dir"])
                if key not in seen and len(items) < limit:
                    seen.add(key)
                    items.append(rel)
        return items
