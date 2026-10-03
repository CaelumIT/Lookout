"""Evidence handling for file-like records: safe path mapping, hashing, text extraction.

The NAS (or any file store) reports paths as the NAS sees them. To read a file, Lookout needs the
same share mounted locally; a path map says which remote folder lives where. Only paths that
resolve inside a mapped folder are ever opened, and files are only ever opened for reading."""
import datetime
import email
import email.policy
import html.parser
import os
import posixpath
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath


class EvidenceError(RuntimeError):
    """A problem reading evidence. The message is safe to show to the user."""


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ContentAccess:
    def __init__(self, path_map, max_hash_bytes=4 * 1024 ** 3, max_text_chars=20000):
        if not path_map:
            raise EvidenceError("A content section needs at least one path_map entry")
        pairs = []
        for e in path_map:
            remote, local = str(e.get("remote", "")), str(e.get("local", ""))
            if not remote.startswith("/") or not local:
                raise EvidenceError("Each path_map entry needs an absolute 'remote' path and a 'local' folder")
            pairs.append((PurePosixPath(posixpath.normpath(remote)), Path(local)))
        self.pairs = sorted(pairs, key=lambda p: -len(p[0].parts))     # most specific folder first
        self.max_hash_bytes = int(max_hash_bytes)
        self.max_text_chars = int(max_text_chars)

    @classmethod
    def from_cfg(cls, cfg):
        if not cfg:
            return None
        return cls(cfg.get("path_map") or [], float(cfg.get("max_hash_gb", 4)) * 1024 ** 3, int(cfg.get("max_text_chars", 20000)))

    def local(self, remote_path):
        """Translate a remote path to a local one, refusing anything that escapes the mapped folders."""
        rp = PurePosixPath(posixpath.normpath("/" + str(remote_path).replace("\\", "/").lstrip("/")))
        for remote, local in self.pairs:
            if rp == remote or remote in rp.parents:
                root = local.resolve()
                target = (root / rp.relative_to(remote)).resolve()          # follows symlinks
                if target != root and root not in target.parents:
                    raise EvidenceError("That path resolves outside the mapped folder (a symbolic link?) and was refused.")
                return target
        raise EvidenceError("That path is not under any folder listed in path_map.")

    def facts(self, remote_path):
        p = self.local(remote_path)
        try:
            st = p.stat()
        except FileNotFoundError:
            raise EvidenceError("The file was not found at the mapped location. Is the share mounted, and has the file moved?")
        if not p.is_file():
            raise EvidenceError("That path is not a regular file.")
        return p, {"path": str(remote_path), "size": st.st_size, "modified": _iso(st.st_mtime)}

    def verify(self, remote_path, want_hash=True):
        """File facts plus a SHA-256 computed while reading, with a check that the file did not change."""
        p, facts = self.facts(remote_path)
        if not want_hash:
            return facts
        if facts["size"] > self.max_hash_bytes:
            raise EvidenceError(f"The file is larger than the {self.max_hash_bytes // 1024 ** 3} GB hashing limit.")
        import hashlib
        h = hashlib.sha256()
        with open(p, "rb") as f:
            before = os.fstat(f.fileno())
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
            after = os.fstat(f.fileno())
        facts.update(sha256=h.hexdigest(), hashed_at=_iso(datetime.datetime.now(datetime.timezone.utc).timestamp()),
                     stable=(before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns))
        return facts

    def text(self, remote_path):
        """Readable text from a file, or None when the type is unsupported. Contents are untrusted."""
        p, _ = self.facts(remote_path)
        return extract_text(p, self.max_text_chars)


# ---------- text extraction (standard library only) ----------
PLAIN = {".txt", ".md", ".log", ".csv", ".tsv", ".json", ".ini", ".cfg", ".conf", ".yml", ".yaml"}
MAX_RAW = 5 * 1024 * 1024


class _Strip(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("script", "style")

    def handle_endtag(self, tag):
        self.skip -= tag in ("script", "style") and self.skip > 0

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def _clip(text, n):
    text = re.sub(r"[ \t]+\n", "\n", text).strip()
    return {"text": text[:n], "truncated": len(text) > n}


def extract_text(path, max_chars=20000):
    ext = Path(path).suffix.lower()
    try:
        if ext in PLAIN:
            with open(path, "rb") as f:
                return _clip(f.read(MAX_RAW).decode("utf-8", "replace"), max_chars)
        if ext in (".html", ".htm"):
            s = _Strip()
            with open(path, "rb") as f:
                s.feed(f.read(MAX_RAW).decode("utf-8", "replace"))
            return _clip(" ".join(s.out), max_chars)
        if ext == ".eml":
            with open(path, "rb") as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
            body = msg.get_body(preferencelist=("plain", "html"))
            content = body.get_content() if body else ""
            head = "\n".join(f"{h}: {msg[h]}" for h in ("From", "To", "Date", "Subject") if msg[h])
            return _clip(head + "\n\n" + content, max_chars)
        if ext == ".docx":
            with zipfile.ZipFile(path) as z:
                info = z.getinfo("word/document.xml")
                if info.file_size > 50 * 1024 * 1024:
                    raise EvidenceError("The document is too large to read safely.")
                root = ET.fromstring(z.read("word/document.xml"))
            ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
            paras = ["".join(t.text or "" for t in p.iter(ns + "t")) for p in root.iter(ns + "p")]
            return _clip("\n".join(paras), max_chars)
    except EvidenceError:
        raise
    except (OSError, KeyError, zipfile.BadZipFile, ET.ParseError, UnicodeError) as e:
        raise EvidenceError(f"The file could not be read as {ext}: {e}")
    return None
