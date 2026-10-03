"""Indicator extraction: IP addresses, domains, URLs, e-mail addresses, hashes, CVE and MITRE IDs.

Done with patterns in code, never by the model, so results are exact and testable. Text is
"refanged" first (hxxp, [.] and similar), because analysts routinely write indicators defanged."""
import ipaddress
import re

_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*://\s*\]|\[:\s*//\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\[at\]|\(at\)", re.I), "@"),
]
URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])")
HASHES = [("sha256", 64), ("sha1", 40), ("md5", 32)]
HASH = {k: re.compile(rf"(?<![A-Fa-f0-9])[A-Fa-f0-9]{{{n}}}(?![A-Fa-f0-9])") for k, n in HASHES}
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
# Extensions that look like top-level domains but are almost always file names in this setting.
# This hides a few real domains (.sh, .py, .md, .zip, .mov); that trade-off is deliberate.
NOT_TLDS = set("""pdf doc docx xls xlsx ppt pptx txt csv json xml html htm exe dll zip rar gz tar bz2 xz iso img bin dat db sql bak
log tmp ini cfg conf yml yaml jpg jpeg png gif bmp svg mp3 mp4 mov avi mkv wav eml msg lnk js py sh bat cmd ps1 md php asp aspx jsp cgi
pl rb java class jar apk dmp pcap evtx reg""".split())

KINDS = ["url", "email", "ipv4", "ipv6", "sha256", "sha1", "md5", "cve", "technique", "domain"]


def refang(text):
    for pat, rep in _REFANG:
        text = pat.sub(rep, text)
    return text


def _host(url):
    m = re.match(r"[a-z]+://(?:[^/@\s]*@)?([^/:?#\s]+)", url, re.I)
    return m.group(1) if m else ""


def extract(text, kinds=None, max_items=50):
    """Return [{"kind", "value"}], de-duplicated, in order of first appearance."""
    if not text:
        return []
    want = set(kinds or KINDS)
    t = refang(str(text))
    found = []                                            # (position, kind, value)

    def add(pos, kind, value):
        if kind in want:
            found.append((pos, kind, value))

    for m in URL.finditer(t):
        url = m.group(0).rstrip(".,;:!?)]}>")
        add(m.start(), "url", url)
    for m in EMAIL.finditer(t):
        add(m.start(), "email", m.group(0).lower())
    # domains: look at text where each URL is reduced to its host and each e-mail to its domain
    reduced = URL.sub(lambda m: " " + _host(m.group(0)) + " ", t)
    reduced = EMAIL.sub(lambda m: " " + m.group(0).split("@", 1)[1] + " ", reduced)
    for m in IPV4.finditer(reduced):
        try:
            ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        add(m.start(), "ipv4", m.group(0))
    for m in IPV6.finditer(reduced):
        try:
            ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        add(m.start(), "ipv6", m.group(0).lower())
    for kind, rx in HASH.items():
        for m in rx.finditer(reduced):
            add(m.start(), kind, m.group(0).lower())
    for m in CVE.finditer(reduced):
        add(m.start(), "cve", m.group(0).upper())
    for m in TECHNIQUE.finditer(reduced):
        add(m.start(), "technique", m.group(0))
    for m in DOMAIN.finditer(reduced):
        d = m.group(0).lower()
        if d.rsplit(".", 1)[-1] in NOT_TLDS or re.fullmatch(r"[\d.]+", d):
            continue
        add(m.start(), "domain", d)

    seen, out = set(), []
    for _, kind, value in sorted(found, key=lambda f: f[0]):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append({"kind": kind, "value": value})
    return out[:max_items]


def search_term(ioc):
    """What to type into another source's search box for this indicator."""
    return _host(ioc["value"]) or ioc["value"] if ioc["kind"] == "url" else ioc["value"]


def defang(value):
    """Safe-to-paste form for reports."""
    return value.replace("http", "hxxp").replace(".", "[.]") if "." in value else value
