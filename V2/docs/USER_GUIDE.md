# Lookout: user guide

A short, plain-language guide to searching with Lookout. You do not need any technical background. If something here does not match what you see, or you need help connecting to a system, ask the person who set Lookout up for you (the guide for them is [INSTALLATION.md](INSTALLATION.md)).

## What Lookout is

Lookout is a search page. You type a word or ask a question, and it looks through the systems your organisation has connected (for example a threat-intelligence platform, an incident database, log records, or files on a storage server). It shows what it found, and an AI helper that runs **on your own computer** suggests what to look at next and can write a short report.

Lookout **only reads**. It never changes your data. Nothing you search for is sent to an internet service.

## What you need before you start

- Lookout running on your computer (your administrator will tell you the address, normally <http://localhost:8765>).
- At least one data source set up for you.
- An AI model chosen (see "Choose a model" below). You only do this once.

## A tour of the screen

```
+---------------------------------------------------------------------+
| Lookout  [Source v] [Simple|Contextual] [ search box ] [Search]     |
|                                   ● Source  ● Ollama   [Model]      |
+-------------+-----------------------------------+-------------------+
| History     | Results                           | Recommendations   |
| (your past  | (cards you can open)              | (AI suggestions,  |
|  searches)  |                                   |  next searches,   |
|             |                                   |  report button)   |
+-------------+-----------------------------------+-------------------+
```

- **Source** menu: appears when there is more than one data source. **All sources** searches everything at once.
- **Simple / Contextual**: two ways to search (explained below).
- **Two coloured dots**: the first is your data source, the second is the AI helper. Green means working. If one is red, hover over it to read why.
- **Model** button: choose which AI model to use.
- **History**: your earlier searches. Click one to run it again.

## Choose a model (first time only)

Click **Model**, pick a name from the list, and press **Save**. If the list is empty, ask your administrator to install a model.

## Two ways to search

### Simple search

Type a name, a word, an address or an ID and press Enter. Examples: `ransomware`, `203.0.113.50`, `CVE-2024-3400`, `whiteboard`.

Use it when you know what you are looking for.

### Contextual search (ask a question)

Click **Contextual**, then type a question in everyday language:

- *What do we know about APT-Example?*
- *How are these two incidents linked?*
- *Show photos from the lobby last September* (only if your files can be filtered that way)

The AI works out which things you mean, Lookout looks each one up, and a panel called **Understood as** shows what it decided. **Always read this panel**: if Lookout picked the wrong thing, rephrase using the exact name, or switch to Simple search.

If you name two or more things, Lookout also shows:

- **Direct links**: where the systems record a relationship between them.
- **Shared connections**: things both of them are connected to.

If a system does not record relationships, Lookout tells you it cannot assess links. It will not guess.

## Reading the results

Each result is a card showing its **type** (for example Incident, Document, Photo), its **name**, a short description, key facts, labels and a date. When several sources are searched together, a small badge shows which source it came from.

- Use the buttons above the cards (**All**, then one per type) to show only one kind.
- **Click a card to open it.** You will see:
  - **Related items**: things connected to this one. Click any of them to search for it.
  - **Indicators in this item**: addresses, domains, file fingerprints and similar clues found in the text. Click one to search for it everywhere.
  - **Evidence** (for files): where the file is stored, its size and dates, and whether any of its text was produced by a machine.
  - A **Get recommendations for this item** button.

## Indicators and "other sources"

An *indicator* is a clue such as an IP address, a web address, an e-mail address, a CVE number or a file fingerprint. When you ask about something across **All sources**, Lookout looks for its indicators in the other systems, and shows a section **Indicators that appear in other sources**.

**Important:** these are *text matches*. They are leads to follow up, not proof that two things are connected. The same address can appear in unrelated files, and no match does not prove there is no connection.

## Working with files as evidence

For results that are files, open the card and look at **Evidence**:

- **Path, size, modified, indexed**: what the file index recorded. "Indexed" is when the file was last scanned.
- **Machine-generated text**: if you see tags such as *ocr*, *summary* or *transcript*, the text shown was produced by software (reading text from a picture, describing an image, or turning speech into text). It can be wrong. **Check the original file** before relying on it.
- **Verify file (SHA-256)**: reads the file and computes its *fingerprint* (called a hash). The result shows the fingerprint, when it was computed, and warns you if the file's size differs from the index or the file changed while it was being read. Only available if your administrator has connected the file storage.
- A fingerprint shows what the file contains **now**. It does not show who handled it or whether it changed earlier. Compare it with the fingerprint recorded when the evidence was collected.

## The AI suggestions (right-hand side)

After a search, the helper writes a short summary: **what to look at first**, **gaps and cautions**, and a **Search next** list. Click any item in that list to run the search.

- **Run after each search** (tick box): turn it off if you only want results.
- **Run again**: asks for a fresh answer.
- **Stop**: stops it early.

## Writing a report (intel bulletin)

Under the suggestions, click **Expand into intel bulletin**. Lookout writes a longer, structured report (key points, background, relationships, indicators, assessment, recommended actions, gaps). If files were involved, it ends with an **Evidence appendix** listing each file, its location, dates, whether it was verified, and which text is machine-generated.

In the report window you can:

- **Copy Markdown**: copy the text to paste elsewhere.
- **Download .md**: save it as a file.
- **Print or save as PDF**: use your browser's print dialog and choose "Save as PDF".
- **Close**: close the window.

A bulletin is a **draft**. Read it against the original records, fix anything wrong, and add your organisation's handling label (for example a TLP marking) before sharing.

## Your search history

Your searches are listed on the left, with how many results each found, and are saved **in this browser on this computer**. Click one to repeat it, click the **×** next to it to remove it, or use **Clear all**. If your searches are sensitive, clear the history when you finish, or use a private browser window.

## Tips for better results

- Start with the exact name or ID if you have it. Add an alias if you know one.
- In Contextual search, put the names in the question and keep it short.
- If you get nothing, try a shorter word, or check the spelling.
- If a source cannot be searched, a red notice appears above the results; the others still work.
- Press **/** on your keyboard to jump to the search box.

## Keep these rules in mind

1. **The AI can be wrong.** It sometimes misreads, leaves things out, or is steered by misleading text inside a record. Open the records it mentions and check.
2. **Machine-generated text is a lead, not a quote.** (Text from pictures, descriptions, summaries, transcripts.)
3. **Matches between systems are leads, not proof.**
4. **Reports are drafts.** Review them before sharing.
5. **Lookout has no password of its own.** Anyone using your computer account can use it, so lock your screen and do not share your session.
6. **Do not copy search results into unapproved places.** Treat them with the same care as the systems they came from.

## If something goes wrong

| What you see | What to do |
| --- | --- |
| A red dot next to a source name | Hover over it to read the reason, then tell your administrator |
| A red dot next to Ollama | The AI helper is not running. Ask your administrator, or start Ollama if you were told how |
| "No model selected" | Click **Model** and choose one |
| The AI answer never appears or is very slow | The model may be too large for your computer. Press **Stop** and ask your administrator about a smaller one |
| "Nothing found" | Try a shorter or different word, or Simple search with the exact name |
| The "Understood as" panel shows the wrong thing | Rephrase with the exact name or use Simple search |
| "The file was not found" when verifying | The file storage may not be connected. Tell your administrator |
| A source says it is "waiting for the Qsirch API reference" | That connection is not finished yet. Use the other sources |
| The page will not load | Check you are using `http://localhost:8765` exactly; other addresses are blocked on purpose |

## Words used in this guide

| Word | Meaning |
| --- | --- |
| **Source** | A system Lookout can search (a platform, a database, a file index) |
| **Record / card** | One result |
| **Related item** | Something a source says is connected to a record |
| **Indicator** | A clue such as an IP address, domain, e-mail address, CVE number or file fingerprint |
| **Pivot** | Searching for a clue from one result in all the other places |
| **Hash / fingerprint (SHA-256)** | A short code computed from a file's contents; if the file changes, the code changes |
| **Machine-generated text** | Text produced by software, such as text read from a photo, an image description, a summary or a transcript |
| **Bulletin** | A longer structured report drafted by the AI helper for you to review |
| **Ollama / model** | The program and the AI model that run on your computer to write the suggestions |
| **TLP** | A handling label for how widely information may be shared (for example CLEAR, GREEN, AMBER, RED) |

## Quick reference

| I want to... | Do this |
| --- | --- |
| Look something up | Type it and press Enter (Simple) |
| Ask a question | Click **Contextual**, type the question |
| Search every system | Choose **All sources** in the Source menu |
| See what is connected | Click a card, then a related item |
| Check a clue everywhere | Click an indicator chip |
| Check a file | Open its card, click **Verify file (SHA-256)** |
| Get a report | Click **Expand into intel bulletin**, then Copy, Download or Print |
| Repeat an old search | Click it in History |
| Jump to the search box | Press **/** |
