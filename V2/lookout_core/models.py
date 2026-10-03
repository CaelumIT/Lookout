"""Normalised shapes that every data source produces. Plain dicts, so they are JSON-ready."""


def _s(v):
    return "" if v is None else str(v)


def _evidence(d):
    """Provenance for file-like records. Only a fixed set of keys is kept."""
    if not isinstance(d, dict):
        return None
    out = {k: d[k] for k in ("path", "size", "modified", "indexed", "sha256", "hashed_at", "stable") if d.get(k) not in (None, "")}
    ai = d.get("ai_derived")
    if isinstance(ai, list) and ai:
        out["ai_derived"] = [str(x) for x in ai]
    return out or None


def record(id, type, name, *, description="", aliases=(), labels=(), meta=(), code=None, date=None,
           date_label="Date", rank=0, observable=False, evidence=None, source=None, source_label=None):
    """One searchable thing: an entity, a row, a document.

    meta       ordered (label, value) pairs shown on the card and given to the model
    code       optional monospace snippet (an indicator pattern, a query, a command line)
    rank       0 is best; sources use it to push reports, observables etc. below core entities
    observable True for low-level items that should not headline a bulletin
    evidence   for files: path, size, modified, indexed, and ai_derived (which text is machine-generated:
               "ocr", "summary", "transcript", ...). Never set by the client; hashes come from the server
    source     id and label of the data source; set by the server, not by adapters
    """
    return {
        "id": _s(id), "type": _s(type).strip() or "Record", "name": _s(name).strip() or _s(id),
        "description": _s(description).strip(),
        "aliases": [a for a in (_s(x).strip() for x in aliases or ()) if a],
        "labels": [l for l in (_s(x).strip() for x in labels or ()) if l],
        "meta": [{"k": _s(k), "v": _s(v)} for k, v in (meta or ()) if _s(v).strip()],
        "code": _s(code).strip() or None, "date": _s(date).strip()[:10] or None,
        "date_label": date_label, "rank": int(rank), "observable": bool(observable),
        "evidence": _evidence(evidence), "source": source, "source_label": source_label,
    }


def relation(type, name, rel, direction="outbound", code=None):
    """A link from a record to something else. `name` is what a user would search for next."""
    return {"type": _s(type).strip() or "Record", "name": _s(name).strip(), "rel": _s(rel).strip() or "related-to",
            "dir": direction if direction in ("inbound", "outbound") else "outbound", "code": _s(code).strip() or None}


def _untrusted_evidence(d):
    """Evidence sent back by a browser: file hashes are never accepted, only the server can compute them."""
    if isinstance(d, dict):
        d = {k: v for k, v in d.items() if k not in ("sha256", "hashed_at", "stable")}
    return d


def coerce_record(d):
    """Rebuild a record received from a client, so later code can rely on its shape."""
    if not isinstance(d, dict):
        raise ValueError("A record must be an object")
    return record(d.get("id", ""), d.get("type"), d.get("name"), description=d.get("description"),
                  aliases=d.get("aliases") if isinstance(d.get("aliases"), list) else [],
                  labels=d.get("labels") if isinstance(d.get("labels"), list) else [],
                  meta=[(m.get("k"), m.get("v")) for m in d.get("meta", []) if isinstance(m, dict)] if isinstance(d.get("meta"), list) else [],
                  code=d.get("code"), date=d.get("date"), date_label=d.get("date_label") or "Date",
                  rank=d.get("rank") or 0, observable=d.get("observable"), evidence=_untrusted_evidence(d.get("evidence")),
                  source=d.get("source"), source_label=d.get("source_label"))


def coerce_relation(d):
    if not isinstance(d, dict):
        raise ValueError("A relation must be an object")
    return relation(d.get("type"), d.get("name"), d.get("rel"), d.get("dir"), d.get("code"))
