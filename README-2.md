# Lookout

Search your [OpenCTI](https://github.com/OpenCTI-Platform/opencti) platform from a clean web UI, and let a **local [Ollama](https://ollama.com) model** suggest what to read first and what to search next.

Everything runs on your machine. Search results are sent only to your own OpenCTI server and your own Ollama instance.

<!-- Add a screenshot here: ![Lookout](docs/screenshot.png) -->

## Features

- **Two search modes**, switched with the toggle next to the search box:
  - **Simple** matches your text directly against OpenCTI.
  - **Contextual** accepts plain-English questions such as *"tell me about links between BlackCat and Fancy Bear"*. The local model works out which entities you mean (including well-known aliases), Lookout looks each one up, fetches their relationships, and works out any direct links and shared connections.
- **Search across OpenCTI** using the GraphQL API: threat actors, intrusion sets, malware, tools, campaigns, attack patterns, vulnerabilities, indicators, reports, observables, and more.
- **Result cards** with type, aliases, description, MITRE ID, CVSS score, dates, labels and indicator patterns. Filter by entity type.
- **Related entities** on demand: open a card to see what it connects to (in both directions), then click any related entity to search for it.
- **Local recommendations** streamed from Ollama: a short summary, what to look at first, gaps and cautions, and clickable "search next" suggestions.
- **Intel bulletin**: one click expands the recommendations into a longer bulletin (key judgments, background, relationships and activity, indicators, assessment, recommended actions, gaps). Copy it as Markdown, download it as a `.md` file, or print it / save it as a PDF.
- **Entity-focused advice**: ask the model about a single result and its relationships.
- **Search history** saved in the browser: re-run, remove one, or clear all.
- **Connection status** lights for OpenCTI and Ollama, plus a model picker built from your installed models.
- Light and dark themes (follows your system), keyboard shortcut `/` to focus search, responsive layout.

## Requirements

- Python 3.8 or newer (standard library only, nothing to install)
- A running OpenCTI platform and an API token
- [Ollama](https://ollama.com) with at least one model pulled, for example `ollama pull llama3.1`
- A modern browser

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/Lookout.git
cd Lookout
python3 server.py
```

Open <http://localhost:8765>, click **Settings**, and fill in:

| Setting | Example | Notes |
| --- | --- | --- |
| OpenCTI URL | `http://localhost:8080` | Base address of the platform. Lookout calls `/graphql` on it. |
| OpenCTI API token | `xxxxxxxx-xxxx-...` | In OpenCTI: your profile, then **API access**. A read-only user is enough. |
| Ollama URL | `http://localhost:11434` | Default Ollama address. |
| Model | `llama3.1:8b` | Pick from the list of installed models. |

Click **Save and test**. Both status lights should turn green.

### Command-line options

```
python3 server.py [--port 8765] [--insecure] [--open]
```

| Option | Purpose |
| --- | --- |
| `--port` | Port for the local page (default `8765`). |
| `--insecure` | Skip TLS certificate checks for upstream servers. Use only for an OpenCTI with a self-signed certificate. |
| `--open` | Open the page in your default browser on start. |

## Contextual search

Switch the toggle to **Contextual** and ask a question:

- *How are BlackCat and Fancy Bear linked?*
- *What tools does APT29 use?*
- *Which groups exploit CVE-2024-3400?*

What happens behind the scenes:

1. The model turns your question into a short list of entities and likely aliases (for example Fancy Bear: APT28).
2. Lookout searches OpenCTI for each one and picks the best match, preferring exact name or alias matches. If it can only find a close match, the answer says so.
3. It loads each entity's relationships and compares them: **direct links** between the entities, and **shared connections** (malware, techniques, targets and so on that appear for more than one of them).
4. The model answers your question from that evidence only. If OpenCTI records no link, the answer says so rather than guessing.

The panel above the results shows how your question was understood, so you can see when it picked the wrong entity. Contextual search needs a model selected in Settings and makes one extra model call, so it is slower than Simple search. Smaller models can mis-extract names; if that happens, rephrase the question or use Simple search.

## Intel bulletin

After a search, click **Expand into intel bulletin** under the recommendations. Lookout gathers relationships for the top results (or reuses those from a contextual search), then the model writes a structured bulletin that streams into a reading view. The bulletin contains a date, a source line, and a handling line that reminds you to assign a TLP marking before sharing. Everything in it comes from the records OpenCTI returned. Review it before it goes to anyone.

## How it works

```
Browser (index.html)  ->  server.py (localhost only)  ->  OpenCTI  /graphql
                                                      ->  Ollama   /api/chat, /api/tags
```

Browsers block a web page from calling OpenCTI or Ollama directly (CORS), so `server.py` serves the page and relays requests. It binds to `127.0.0.1` only, rejects requests addressed to any other host, and rejects cross-origin requests. Streaming from Ollama passes through token by token.

In Simple mode, when you search, Lookout sends the top results (trimmed descriptions, labels, IDs, dates) to the model along with a system prompt that tells it to use only the supplied data, ignore any instructions found inside that data, and finish with a list of suggested search terms. Those suggestions become the clickable chips.

## Privacy and security

- Your OpenCTI token is stored in your browser's local storage, not in this repository.
- Search history is stored in your browser's local storage.
- No telemetry, no external requests. The page loads no external scripts or fonts.
- The relay is meant for local use. Do not expose it on a network interface or put it behind a public reverse proxy.
- Data from OpenCTI is treated as untrusted: it is HTML-escaped before display and the model is told to ignore instructions embedded in it. Small models can still be manipulated or make mistakes, so verify anything important in OpenCTI.

## Troubleshooting

**OpenCTI light is red.** Check the URL and token in Settings. Hover the light for the exact error. `401` or "not authenticated" means the token is wrong or lacks access.

**Search fails with a GraphQL error.** Lookout tries the OpenCTI 6.x schema (`ThreatActorGroup`), then the 5.x schema (`ThreatActor`), then a reduced field set. If all fail, the error is shown on screen. Open an issue with the message and your OpenCTI version.

**Ollama light is red or the model does not answer.** Run `ollama serve`, confirm the model is installed with `ollama list`, and check the Ollama URL. No Ollama CORS settings are needed, because requests go through the relay.

**Self-signed certificate errors.** Start the server with `--insecure`.

**Contextual search picks the wrong entity.** Check the "Understood as" panel above the results. Try the exact name or a well-known alias in your question, or switch to Simple search.

**Bulletin is cut off or ignores some data.** Bulletins use a larger context window (12K tokens). If your model or hardware limits that, pick a model with a longer context or a smaller search.

**Recommendations are generic or wrong.** Try a larger model (8B parameters or more works noticeably better), or search for something more specific so the results are more focused.

## Project layout

```
index.html   The whole UI (HTML, CSS and JavaScript in one file)
server.py    Local relay and static file server (Python standard library)
```

## Status

Early version. It has been syntax-checked and the relay has been tested against a mock upstream, but the GraphQL queries are written from the OpenCTI schema and may need tweaks for specific platform versions. Issues and pull requests are welcome.

## License

Add a license of your choice (MIT is a common default) before publishing.
