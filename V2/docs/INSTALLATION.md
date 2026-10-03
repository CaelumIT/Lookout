# Lookout: installation and configuration guide

This guide takes you from nothing to a working installation, then through connecting each kind of data source, running Lookout as a service, and fixing common problems. If you only want to try Lookout, do sections 1 to 4 and stop.

Read [SECURITY.md](SECURITY.md) before connecting real data. The short version: run Lookout on a machine only you use, and give every source a read-only account.

## Contents

1. [Requirements](#1-requirements)
2. [Get the code](#2-get-the-code)
3. [Try the demo (no servers needed)](#3-try-the-demo-no-servers-needed)
4. [Install Ollama and a model](#4-install-ollama-and-a-model)
5. [Configuration reference](#5-configuration-reference)
6. [Connect your data sources](#6-connect-your-data-sources)
7. [Give Lookout access to files (evidence)](#7-give-lookout-access-to-files-evidence)
8. [First run and verification checklist](#8-first-run-and-verification-checklist)
9. [Run Lookout as a service](#9-run-lookout-as-a-service)
10. [Remote access](#10-remote-access)
11. [Update, back up, uninstall](#11-update-back-up-uninstall)
12. [Install the OpenCTI connector](#12-install-the-opencti-connector)
13. [Run the tests](#13-run-the-tests)
14. [Troubleshooting](#14-troubleshooting)
15. [Reference: files, ports and environment variables](#15-reference-files-ports-and-environment-variables)

## 1. Requirements

| Item | Requirement |
| --- | --- |
| Operating system | Developed and tested on **Linux**. macOS and Windows should work but have not been tested. |
| Python | **3.11 or newer** (the configuration file is TOML). Check with `python3 --version`. |
| Ollama | A current version, with at least one model pulled ([section 4](#4-install-ollama-and-a-model)) |
| Browser | A current Chrome, Edge, Firefox or Safari |
| Disk | Small (the code is a few hundred KB); models need several GB each |
| Memory and GPU | Set by the model you choose. As a rough guide, an 8-billion-parameter model needs around 5 to 8 GB of free memory (more for the large context windows used by bulletins) and is much faster on a GPU. Check Ollama's documentation for current figures. |
| Network | Reach to each data source, and to Ollama |
| Optional drivers | `pymysql` for MySQL/MariaDB, `psycopg` for PostgreSQL. Everything else uses the standard library. |

Lookout needs no internet access once installed, except to download Ollama, models and optional drivers.

## 2. Get the code

```bash
git clone https://github.com/YOUR-USERNAME/Lookout.git
cd Lookout
```

Or download the repository as a zip file and unpack it. All commands below are run from the repository's top folder unless stated.

**Recommended: use a virtual environment** so optional drivers stay separate from the system Python:

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
```

Install optional drivers only if you need them:

```bash
pip install pymysql                  # MySQL or MariaDB
pip install "psycopg[binary]"        # PostgreSQL
```

(`requirements-optional.txt` lists the same drivers.) SQLite, Elasticsearch, OpenCTI and Qsirch need nothing extra.

## 3. Try the demo (no servers needed)

The demo uses synthetic data only: a small SQLite database of made-up threat actors, and sample file records with sample evidence files. It needs Ollama only for the AI parts.

```bash
python3 examples/make_demo.py
python3 web/server.py --config examples/lookout.demo.toml
```

Run these **from the repository's top folder**: the demo configuration uses paths relative to it. You should see:

```
Lookout is running at http://localhost:8765  (2 data source(s): intel, files)  Ctrl+C to stop
```

Open <http://localhost:8765>. Choose **All sources**, click **Model** and pick a model, then search `203.0.113.50` or switch to **Contextual** and ask *"What do we know about APT-Example?"*. Open a result to see its evidence panel and click **Verify file (SHA-256)**.

Stop the server with Ctrl+C.

## 4. Install Ollama and a model

1. Install Ollama from <https://ollama.com> following the instructions for your operating system.
2. Download a model. A good starting point is an instruction-following model of about 8 billion parameters:
   ```bash
   ollama pull llama3.1:8b
   ```
   Larger models answer better and need more memory. Very small models often fail to extract names from questions and to follow the required answer structure.
3. Check that Ollama works:
   ```bash
   ollama list
   curl http://localhost:11434/api/tags
   ```
4. Leave Ollama listening on `127.0.0.1` (the default) when it runs on the same machine as Lookout. If it must run on another machine, see [SECURITY.md](SECURITY.md#8-risks-specific-to-ai) first: Ollama has no authentication.

The model is chosen in the web page (the **Model** button), or you can set `default_model` in the configuration.

## 5. Configuration reference

Lookout reads one TOML file. Create yours from the example:

```bash
cp lookout.example.toml lookout.toml
chmod 600 lookout.toml               # keep it private
```

Edit it, **keep only the sources you need, and delete or comment out the rest**. Start the server with:

```bash
python3 web/server.py --config lookout.toml
```

(or set the `LOOKOUT_CONFIG` environment variable instead of `--config`; `--port` and `--open` are also available.)

Any value can be written as `"${NAME}"`; Lookout replaces it with the environment variable `NAME` at start-up and stops with a clear message if it is not set. Use this for every secret.

### 5.1 Global sections

```toml
[server]
port = 8765                          # the web page is http://localhost:<port>

[ollama]
url = "http://localhost:11434"
timeout = 600                        # seconds to wait for the model
# default_model = "llama3.1:8b"      # used until someone picks a model in the page
```

### 5.2 Settings every source accepts

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Short unique name: letters, digits, `-` or `_` |
| `kind` | yes | `opencti`, `elasticsearch`, `opensearch`, `mysql`, `mariadb`, `postgres`, `sqlite` or `qsirch` |
| `label` | no | Name shown in the page (default: the id) |
| `description` | no | One line telling the model what this data is. Worth writing. |
| `examples` | no | Starter searches shown on the empty screen |
| `questions` | no | Starter plain-English questions |
| `[sources.content]` | no | Lets Lookout read and hash the files behind records ([section 7](#7-give-lookout-access-to-files-evidence)) |

### 5.3 OpenCTI (`kind = "opencti"`)

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | required | Base address, for example `https://opencti.example.internal` (Lookout adds `/graphql`) |
| `token` | none | API token of a read-only user |
| `verify_tls` | `true` | Set `false` only for a self-signed certificate on a test system |
| `timeout` | `60` | Seconds |

### 5.4 Elasticsearch and OpenSearch (`kind = "elasticsearch"` or `"opensearch"`)

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | required | For example `https://es.example.internal:9200` |
| `index` | `*` | Index name or pattern, for example `logs-*` |
| `api_key` | none | Preferred. Or use `username` and `password` |
| `verify_tls` | `true` | |
| `ca_file` | none | Path to a certificate authority file for private certificates |
| `timeout` | `30` | Seconds |

`[sources.mapping]` says how documents become records. Values are dotted field paths such as `event.category`.

| Key | Meaning |
| --- | --- |
| `name` | Field used as the title (falls back to `name`, `title`, `message`, `rule.name`, `event.action`) |
| `description`, `date`, `aliases`, `labels`, `code` | Optional fields |
| `type` or `type_value` | A field holding the type, or a fixed type name (default `Document`) |
| `search_fields` | Fields to search, with optional boosts like `message^3` (default: all fields) |
| `meta` | Inline table of `Label = "field.path"` facts shown on cards |
| `pivots` | Inline table of `Type = "field.path"` (or a list of paths). Their values become "related" items. |
| `pivot_rel` | Wording for those links (default `mentions`) |

### 5.5 SQL databases (`kind = "mysql"`, `"mariadb"`, `"postgres"` or `"sqlite"`)

| Key | Default | Meaning |
| --- | --- | --- |
| `host`, `port`, `user`, `password`, `database` | `localhost`, 3306 (MySQL/MariaDB) or 5432 (PostgreSQL) | Connection details |
| `ssl_ca` | none | MySQL/MariaDB only: certificate authority file |
| `connect_timeout`, `read_timeout` | `5`, `30` | Seconds |
| `path` | required for SQLite | Database file (opened read-only; relative paths are relative to where you start the server) |
| `max_rows` | `100` | Most rows returned per table per search |

One `[[sources.entities]]` block per table you want searchable:

| Key | Required | Meaning |
| --- | --- | --- |
| `table`, `id`, `name` | yes | Table, key column, title column |
| `type` | no | Label for these records (default: the table name) |
| `description`, `aliases`, `labels`, `date`, `code` | no | Columns. `aliases` and `labels` are text separated by `;` `,` or `\|` |
| `search` | no | Columns to search (default: the name column) |
| `search_mode` | no | `like` (default) or `fulltext` (MySQL/MariaDB only; needs a FULLTEXT index on the search columns) |
| `meta` | no | Inline table of `Label = "column"` facts |

Optional `[[sources.relations]]` blocks give relationships. You write a `SELECT` with a `:id` placeholder for the key of the record being expanded:

| Key | Meaning |
| --- | --- |
| `entity` | The `type` (or table) this applies to |
| `sql` | A single `SELECT` or `WITH ... SELECT`. Must return a `name` column; may also return `type`, `rel`, `dir` (`outbound`/`inbound`), `code` |
| `rel`, `type`, `direction` | Defaults used when the query does not return those columns |

Column and table names are checked when the server starts; `test` (the status dot) also runs each query once.

### 5.6 QNAP Qsirch (`kind = "qsirch"`)

Work in progress: use `backend = "fixture"` with sample data until the real backend exists ([QSIRCH.md](QSIRCH.md)).

| Key | Meaning |
| --- | --- |
| `backend` | `http` (default; reports that it is waiting for the API reference) or `fixture` |
| `fixture` | Path to the sample JSON file (for `fixture`) |
| `[sources.mapping]` | Field names in the sample (or, later, real) data: `id` and `name` or `path` are required; others: `size`, `modified`, `indexed`, `taken`, `category`, `snippet`, `tags`, `people`, `objects`, `places`, `ocr`, `summary`, `transcript`, `meta`, `type_map` |

## 6. Connect your data sources

Do the steps for each source you use, then check its status dot ([section 8](#8-first-run-and-verification-checklist)).

### 6.1 OpenCTI

1. In OpenCTI, create a user for Lookout. Give it a role with **read-only** access to knowledge, in groups limited to the markings the analyst may see.
2. Copy that user's API token (shown in the user's profile under API access).
3. Set it in your environment: `export OPENCTI_TOKEN=...`
4. Add to `lookout.toml`:
   ```toml
   [[sources]]
   id = "opencti"
   kind = "opencti"
   label = "OpenCTI"
   url = "https://opencti.example.internal"
   token = "${OPENCTI_TOKEN}"
   ```
5. If you use a private certificate authority, install its certificate in your system trust store. Avoid `verify_tls = false`.

### 6.2 Elasticsearch or OpenSearch

1. Create an API key that can only **read** the index pattern ([SECURITY.md](SECURITY.md#7-least-privilege-setup-for-each-source) has an example). Export it: `export ES_API_KEY=...`
2. Look at one document in your index and decide which fields hold the title, time, category and, for pivoting, the hosts, users and IP addresses.
3. Add a source with a mapping, for example:
   ```toml
   [[sources]]
   id = "logs"
   kind = "elasticsearch"
   label = "Security logs"
   description = "Authentication and endpoint events from our SIEM"
   url = "https://es.example.internal:9200"
   index = "logs-*"
   api_key = "${ES_API_KEY}"
   ca_file = "/etc/ssl/certs/internal-ca.pem"
     [sources.mapping]
     name = "message"
     date = "@timestamp"
     type = "event.category"
     search_fields = ["message^3", "host.name", "user.name", "source.ip"]
     meta = { Action = "event.action", Host = "host.name" }
     pivots = { Host = "host.name", User = "user.name", IP = "source.ip" }
   ```

### 6.3 MySQL or MariaDB

1. `pip install pymysql` (in your virtual environment).
2. Create a user that can only `SELECT` the tables you will search ([SECURITY.md](SECURITY.md#7-least-privilege-setup-for-each-source)). Export its password: `export INCIDENTS_DB_PASSWORD=...`
3. Describe each table and, if you want relationships, the join queries:
   ```toml
   [[sources]]
   id = "incidents"
   kind = "mariadb"
   label = "Incident database"
   host = "db.example.internal"
   user = "lookout_ro"
   password = "${INCIDENTS_DB_PASSWORD}"
   database = "secops"
   ssl_ca = "/etc/ssl/certs/internal-ca.pem"
     [[sources.entities]]
     table = "incidents"
     type = "Incident"
     id = "id"
     name = "title"
     description = "summary"
     date = "created_at"
     search = ["title", "summary", "notes"]
     meta = { Status = "status", Severity = "severity" }

     [[sources.relations]]
     entity = "Incident"
     rel = "affected"
     type = "Asset"
     sql = """
       SELECT a.hostname AS name
       FROM incident_assets ia JOIN assets a ON a.id = ia.asset_id
       WHERE ia.incident_id = :id
     """
   ```

### 6.4 PostgreSQL

Same as above with `kind = "postgres"`, `pip install "psycopg[binary]"`, and a role granted `SELECT` on the named tables. `search` uses `ILIKE` (case-insensitive). The `fulltext` search mode is not available. TLS settings use the driver's defaults; to require TLS, enforce it on the server (for example in `pg_hba.conf`).

### 6.5 SQLite

Useful for trying things out or for exported data:

```toml
[[sources]]
id = "local"
kind = "sqlite"
label = "Local database"
path = "/path/to/file.db"
  [[sources.entities]]
  table = "notes"
  id = "id"
  name = "title"
  search = ["title", "body"]
```

### 6.6 QNAP Qsirch

Not connected to a real NAS yet. To explore the feature, use the sample configuration in `examples/lookout.demo.toml`. When the Qsirch API reference is available, follow the hand-over steps in [QSIRCH.md](QSIRCH.md).

## 7. Give Lookout access to files (evidence)

Skip this unless a source describes files (currently the Qsirch sample data) and you want **Verify file**, file text and a hash in bulletins.

1. **Mount the share read-only** on the machine running Lookout. Linux examples (adapt to your environment):
   ```bash
   sudo mkdir -p /mnt/nas/Evidence
   # SMB/CIFS, with credentials in a root-owned file (mode 600) rather than on the command line
   sudo mount -t cifs //nas.example.internal/Evidence /mnt/nas/Evidence -o ro,credentials=/etc/lookout-nas.cred
   # or NFS
   sudo mount -t nfs -o ro nas.example.internal:/share/Evidence /mnt/nas/Evidence
   ```
   Prefer mounting a **snapshot** or an **immutable** share.
2. Add a `[sources.content]` section to the source, mapping the folder **as the file index reports it** to the local mount:
   ```toml
     [sources.content]
     path_map = [{ remote = "/share/Evidence", local = "/mnt/nas/Evidence" }]
     # max_hash_gb = 4                 # refuse to hash larger files
     # max_text_chars = 20000          # text shown per file
   ```
3. Restart Lookout. Open a file result and click **Verify file (SHA-256)**. If it says the file was not found, the remote path in the index does not match your `remote` prefix, or the share is not mounted.

On Windows, mount the share to a drive letter and use forward slashes in `local` (for example `local = "Z:/Evidence"`). This has not been tested.

## 8. First run and verification checklist

1. Start the server: `python3 web/server.py --config lookout.toml`. A "Configuration problem" message names what to fix.
2. Open <http://localhost:8765>. Two coloured dots appear at the top: the data source and Ollama. **Hover a dot** to see the details. Green means working; red shows the reason.
3. Click **Model** and choose a model. The list comes from Ollama.
4. For each source, search a term you know exists and confirm the first results are right.
5. Open a result. Confirm related items appear (if the source has relationships) and that chips like indicators are clickable.
6. Switch to **Contextual** and ask a question whose answer you already know, naming two things. Check the "Understood as" panel matches what you meant.
7. If you have several sources, try **All sources**.
8. If you configured files, verify one and compare the hash with one you computed yourself (`sha256sum file`).
9. Generate a bulletin and read it against the source records.

## 9. Run Lookout as a service

Running it by hand in a terminal is fine for personal use. To start it automatically on Linux, here is an **example** systemd unit (adapt paths and user; not tested here):

```ini
# /etc/systemd/system/lookout.service
[Unit]
Description=Lookout
After=network-online.target

[Service]
User=lookout
WorkingDirectory=/opt/lookout
EnvironmentFile=/etc/lookout/lookout.env
ExecStart=/opt/lookout/.venv/bin/python web/server.py --config /etc/lookout/lookout.toml
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/mnt/nas

[Install]
WantedBy=multi-user.target
```

Setup:

```bash
sudo useradd --system --home /opt/lookout lookout
sudo install -d -m 750 -o root -g lookout /etc/lookout
sudo install -m 640 -o root -g lookout lookout.toml /etc/lookout/lookout.toml
sudo install -m 640 -o root -g lookout lookout.env /etc/lookout/lookout.env   # lines like OPENCTI_TOKEN=...
sudo systemctl daemon-reload && sudo systemctl enable --now lookout
journalctl -u lookout -f
```

A service is still reachable only on `localhost` of that machine. On Windows, use Task Scheduler to run the same command at log-on; on macOS, a launch agent. Neither has been tested.

There is no container image for the web app. Because the server deliberately binds only to `127.0.0.1`, publishing its port from a container would not work without changing that, which would remove a safeguard; add authentication first (see [SECURITY.md](SECURITY.md#13-known-gaps)).

## 10. Remote access

Do not expose Lookout on a network. To use it from another computer, tunnel over SSH so your browser still talks to `localhost`:

```bash
ssh -L 8765:localhost:8765 you@lookout-host
```

Then browse to <http://localhost:8765> on your own machine.

## 11. Update, back up, uninstall

**Update.** Stop the server, `git pull` (or unpack the new version over the old), reinstall optional drivers if needed, and start it again. Read the notes in the repository for any change to the configuration format. Run the tests ([section 13](#13-run-the-tests)).

**Back up.** Only your configuration file matters (`lookout.toml`, plus your environment file). Lookout stores no data on the server. Search history lives in each browser.

**Uninstall.** Stop the service, delete the folder (and `/etc/lookout` and the unit file if you created them), and revoke the read-only accounts you created in each source. Clear the site's local storage in your browser if you want to remove its search history.

## 12. Install the OpenCTI connector

The connector is separate from the web app and runs inside your OpenCTI deployment. In summary:

1. Create a dedicated, least-privilege OpenCTI user for it and note its token.
2. Put the Lookout repository next to your OpenCTI `docker-compose.yml` as `./lookout`.
3. Add the service from `connector/docker-compose.yml` and set `OPENCTI_VERSION`, `CONNECTOR_LOOKOUT_ID` (a new UUID) and `CONNECTOR_LOOKOUT_TOKEN` in your `.env`. **pycti must match your OpenCTI version.**
4. Make Ollama reachable from the container (see the security note about exposing it).
5. `docker compose up -d --build connector-lookout`, then check **Data, Ingestion, Connectors** in OpenCTI.

Full steps, settings and limitations: [../connector/README.md](../connector/README.md).

## 13. Run the tests

From the repository's top folder:

```bash
python3 -m unittest discover -s tests
```

It should report `Ran 83 tests ... OK` in a few seconds. The tests use SQLite, local mock servers and the sample data; they need no network and no Ollama. Add `-v` for details.

## 14. Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `ModuleNotFoundError: tomllib` or a syntax error at start | Python older than 3.11 | Install Python 3.11 or newer and use it |
| `Configuration problem: Config file not found` | Wrong path or folder | Run from the repository's top folder, or pass `--config /full/path` |
| `Environment variable X is not set` | A `${X}` in the config has no value | `export X=...` (or add it to the service's environment file) and restart |
| `Duplicate source id` / `unknown kind` / `not a plain table or column name` | Typo in the configuration | Fix the setting the message names |
| Source dot is red | Wrong address, token or credentials; network; certificate | Hover the dot for the reason; test the same address with `curl` from the same machine |
| `rejected the API token` | Wrong or expired OpenCTI token, or user lacks access | Create a new token for the read-only user |
| `Could not reach ...` | Service down, firewall, wrong port | Check the service and the route from this machine |
| Certificate errors | Private certificate authority | Use `ca_file` (Elasticsearch), `ssl_ca` (MySQL/MariaDB) or the system trust store; avoid `verify_tls = false` |
| `The Python driver for mysql is not installed` | Missing optional driver | `pip install pymysql` (or `psycopg[binary]`) in the environment that runs Lookout |
| `The database rejected a query: ... no such column` | A column name in the config is wrong | Fix the name; the status check names the failing query |
| Ollama dot is red | Ollama not running or wrong URL | Run `ollama serve`; check `[ollama] url` |
| "No model selected" | No model chosen | Click **Model**; or `ollama pull` one first |
| The model answers with a long wait or an error | Model too large for memory, or timeout | Try a smaller model, close other programs, raise `[ollama] timeout` |
| Contextual search picks the wrong thing | Small model or ambiguous names | Use exact names or aliases, a larger model, or Simple search |
| Qsirch source says it is waiting for the API reference | The real backend is not built yet | Use `backend = "fixture"` for now ([QSIRCH.md](QSIRCH.md)) |
| `That path is not under any folder listed in path_map` | The file's path in the index does not start with your `remote` value | Compare the path shown in the evidence panel with `path_map` |
| `The file was not found at the mapped location` | Share not mounted, or file moved | Check the mount; check the file exists at the local path |
| `resolves outside the mapped folder` | A symbolic link points outside the mount | Expected protection; map the real folder instead |
| Port already in use | Another program on 8765 | `--port 8766` or change `[server] port` |
| Page cannot reach the server | Server stopped, or not using `localhost` in the address | Use `http://localhost:8765` (other host names are refused on purpose) |
| Search history shows old entries | Stored in the browser | Use **Clear all** in the history panel |

If something fails and the message is not enough, the server's standard error output shows one line per request and any internal error.

## 15. Reference: files, ports and environment variables

| Item | Value |
| --- | --- |
| Web page and API | `http://localhost:8765` (change with `--port` or `[server] port`) |
| Ollama | `http://localhost:11434` by default |
| Configuration | `lookout.toml` (your copy of `lookout.example.toml`); excluded from version control by `.gitignore` |
| `LOOKOUT_CONFIG` | Alternative to `--config` |
| `${NAME}` in the configuration | Read from the environment at start-up |
| Browser storage | Keys `lookout.settings` and `lookout.history` in the page's local storage |
| Server storage | None (verified hashes are kept in memory only) |
| Connector variables | See [../connector/README.md](../connector/README.md) |
