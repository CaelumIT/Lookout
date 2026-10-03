# Qsirch integration: status and hand-over checklist

Lookout can search files on a QNAP NAS through Qsirch and use them as evidence alongside other sources (OpenCTI, databases, logs). Most of the integration is built and tested. **One piece is missing: talking to the real Qsirch API**, because the API reference is served by the NAS itself and is not published on the public web. Nothing in this repository guesses an endpoint or field name.

## What exists today

| Area | State |
| --- | --- |
| `kind = "qsirch"` source, record mapping from configurable field paths | done, tested on sample data |
| Relations as pivots: people, tags, objects, places, folder | done |
| Filters (category, date range, path contains), set from questions like "photos from last March" | done; applied in code when the backend cannot filter |
| Evidence block on every file record (path, size, times, which text is machine-generated) | done |
| Reading and hashing files through a mounted share, with path-escape protection | done, tested |
| Text extraction for .txt .md .csv .json .log .html .eml .docx | done (no PDF, no OCR) |
| Indicator extraction (IPs, domains, URLs, e-mail, hashes, CVE, MITRE IDs) with refanging | done, tested |
| Search across all sources, with indicator pivots between sources | done, tested |
| Evidence appendix on bulletins (path, times, hash if verified, AI-derived flags) | done |
| **`HttpBackend`: login, search, fetch one, thumbnails, capability detection** | **waiting for the API reference** |
| Default field mapping for the real response format | waiting for the API reference |
| Thumbnails in result cards | waiting (needs the thumbnail endpoint) |

You can try everything except the real backend now: `python3 examples/make_demo.py`, then `python3 web/server.py --config examples/lookout.demo.toml`, pick **All sources**, and ask "What do we know about APT-Example?". The sample actor's IP address and domain turn up in the sample files, and **Verify file** hashes them from `examples/evidence/`. The sample file format (`examples/qsirch_synthetic.json`) is invented for development; it is not the Qsirch format.

## What Qsirch can do (from QNAP's public pages)

- Qsirch 7.1.0 adds **AI Mode**: documents, images, video and audio searchable by description, summaries, video moments and audio transcripts, with inference on the NAS. It needs a NAS in the x74 series or above with a 16 GB+ GPU.
- Without AI Mode: keyword search including file metadata (author, EXIF, IPTC), AI OCR for images, and AI semantic image search (needs QNAP AI Core, 64-bit x86, 8 GB RAM, QTS 5.0.1 or later).
- Qsirch's own RAG search is a separate feature and can use cloud models; Lookout does not use it.
- QNAP's **MCP Assistant** (QTS 5.2 or later) is a second possible route: it exposes Qsirch keyword-and-filter search and category listing with token authentication.

## When you have the API reference, send me

1. The page at `http://<NAS>:<port>/qsirch/latest/api` (save it, or export its OpenAPI/JSON file if it has one).
2. Sanitised sample responses for: a keyword search that returns a document, a photo (ideally with OCR text or tags) and a video (ideally with a transcript), plus a fetch of one item.
3. How you log in to the NAS for scripts (a QTS account, an API token, 2-step verification on or off).
4. Your NAS model and whether AI Mode is available, and the Qsirch and QTS/QuTS versions.

## What I will do with it

1. Write `HttpBackend` (login, search with server-side filters, fetch one, thumbnail, capability detection) with tests that replay your recorded responses.
2. Fill in the default `[sources.mapping]` so the config needs only the URL and credentials.
3. Show thumbnails and an "open in File Station" link on cards.
4. Report AI Mode, semantic search and OCR availability in the connection check, and let the question planner use semantic search where available.
5. Decide, with you, between the REST route and the MCP route if the REST reference proves thin.

## Handling files as evidence

- Use a **dedicated read-only NAS account**, and where possible point `path_map` at a **snapshot or immutable share**, so reading files cannot alter them.
- The file path always comes from the data source's own record, never from the browser. Paths are checked against `path_map`, symbolic links that leave the mapped folder are refused, and files are only opened for reading.
- A hash is computed only when you click **Verify file** (or the API is called), is labelled with when it was computed, and is flagged if the file changed while being read. Bulletins list a hash only if it was verified in that session.
- Text from OCR, image descriptions, summaries and transcripts is machine-generated. It is labelled as such on cards and in bulletins, and the prompts tell the model never to present it as a verbatim quote.
- Matches between sources are text matches on an indicator. They are leads, not proof of a relationship, and the interface says so.
- File contents are untrusted input (a document can contain instructions aimed at a model). The same handling as database text applies, but review file-derived output with extra care.
