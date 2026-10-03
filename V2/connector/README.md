# Lookout connector for OpenCTI

An OpenCTI **internal-enrichment connector** that uses a **local Ollama model** to write analyst-ready Notes directly inside the platform. It is the in-platform companion to the Lookout web app and shares its code (`lookout_core/`).

| You do this in OpenCTI | Lookout does this |
| --- | --- |
| Open an entity (threat actor, intrusion set, malware, campaign, technique, vulnerability, report, incident), choose **Enrichment**, then **Lookout** | Reads the entity and its relationships, asks your local model for an intel bulletin (or short summary), and attaches the result as a **Note** |
| Create a **Request for information** (RFI) case with a plain-English question in its title or description, and run **Lookout** on it | Works out which entities the question mentions, looks them up, finds direct links and shared connections, and attaches an answer Note to the case |

Nothing leaves your environment except the call to your own Ollama server.

## What this is not

OpenCTI's extension mechanism is connectors that talk to the platform through its API. As far as I know it has no plugin API for adding your own panels or pages to the web UI, so a live search box cannot be added without forking the frontend (not recommended). The interactive, multi-source search stays in the Lookout web app.

## Quick start (Docker)

1. In OpenCTI, create a **dedicated user** for this connector (see Security) and copy its API token.
2. Put the whole Lookout repository next to your OpenCTI `docker-compose.yml` as `./lookout`. The connector builds from the repository root because it shares `lookout_core/`.
3. Add the service from `connector/docker-compose.yml` to your compose file and set in `.env`:
   ```
   OPENCTI_VERSION=<the version your platform runs, e.g. 6.5.0>
   CONNECTOR_LOOKOUT_ID=<a new UUIDv4>
   CONNECTOR_LOOKOUT_TOKEN=<the connector user's token>
   ```
4. Make Ollama reachable from the container. If it runs on the Docker host, start it with `OLLAMA_HOST=0.0.0.0 ollama serve` and keep the `host.docker.internal` mapping. Pull the model: `ollama pull llama3.1:8b`.
5. `docker compose up -d --build connector-lookout`
6. In OpenCTI open **Data, Ingestion, Connectors** and confirm "Lookout (local AI)" is registered, then use **Enrichment** on an entity.

**pycti must match your OpenCTI version.** The Dockerfile takes it from the `PYCTI_VERSION` build argument, which the compose file sets from `OPENCTI_VERSION`.

### Running without Docker

```bash
pip install pycti==<your OpenCTI version> -r connector/requirements.txt
cp connector/src/config.yml.sample connector/src/config.yml     # then edit it
PYTHONPATH=. python3 connector/src/main.py                      # from the repository root
```

## Configuration

Environment variables (or `lookout:` in `config.yml`). The standard `OPENCTI_*` and `CONNECTOR_*` variables work as for any OpenCTI connector.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOKOUT_OLLAMA_MODEL` | required | Model name, for example `llama3.1:8b` |
| `LOOKOUT_OLLAMA_URL` | `http://host.docker.internal:11434` | Ollama address |
| `LOOKOUT_OLLAMA_TIMEOUT` | `600` | Seconds to wait for the model |
| `LOOKOUT_NUM_CTX` | `12288` | Context window requested for answers |
| `LOOKOUT_OUTPUT` | `bulletin` | `bulletin` (long) or `summary` (short) for entities |
| `LOOKOUT_QUESTION_TYPES` | `Case-Rfi` | Entity types treated as plain-English questions; they must also be in `CONNECTOR_SCOPE` |
| `LOOKOUT_MAX_TLP` | `TLP:RED` | Refuse entities marked above this level, so nothing above it reaches the model |
| `LOOKOUT_LINK_FOUND_ENTITIES` | `false` | For questions: also attach the answer Note to every entity found (see Security) |
| `LOOKOUT_LABEL` | `ai-generated` | Label added to every Note; empty disables it |
| `CONNECTOR_AUTO` | `false` | Keep `false`: run on demand, not on every new entity |

## How it works

```
OpenCTI --enrichment request--> connector --GraphQL (read, via pycti)--> OpenCTI
                                    |--/api/chat--> Ollama (local)
                                    |--api.note.create--> OpenCTI (Note, same markings)
```

The connector uses the shared `OpenCTISource` adapter with pycti's authenticated client as its transport, so no second credential is needed. Matching, link analysis, prompts and the TLP policy all come from `lookout_core`. Only `connector/src/lookout_connector/connector.py` imports pycti.

## Security

- **The connector reads with its own account, not the analyst's.** Anyone who can run it can receive a Note built from data the connector's user can see, which may be more than they can see. Create a dedicated user whose groups and allowed markings are no broader than the least-privileged analyst who may trigger it, with only read and create-Note access.
- **Markings:** a Note inherits the markings of the entity (or case) it is attached to. For questions, `LOOKOUT_LINK_FOUND_ENTITIES=false` keeps the answer on the case only, because attaching it to every found entity would show text derived from one entity on others with different markings.
- **`LOOKOUT_MAX_TLP`:** the default allows everything because Ollama is local. If your Ollama is on another machine, set a limit.
- **Untrusted data:** database text is given to the model as JSON with instructions to ignore commands inside it. Every Note carries an "AI-generated, review before use" footer and label.

## Limitations and what to verify first

- **Not yet run against a live OpenCTI.** The shared logic is covered by the repository's tests, and the connector's own logic was run with a stubbed pycti, which checks my code but not pycti's real behaviour. On your version, check that: the connector registers and appears under Enrichment; running it on an entity creates a Note on that entity; the Note carries the entity's markings; and an RFI case offers Lookout (if your version does not offer enrichment on cases, set `LOOKOUT_QUESTION_TYPES` and `CONNECTOR_SCOPE` to a type that does).
- **Repeated runs create repeated Notes.**
- **Name-based matching.** Direct links and shared connections compare names and aliases as text.
- **One entity per run for bulletins.**
- pycti logs GraphQL errors itself, so on a 5.x platform you may see "Unknown type" errors logged on the first query while the schema fallback finds the right variant.
