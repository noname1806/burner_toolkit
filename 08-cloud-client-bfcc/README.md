# Burner Forensics Cloud Client (BFCC)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Status](https://img.shields.io/badge/Status-Lab%20use%20only-orange.svg)](#legal-use)
[![License](https://img.shields.io/badge/License-Choose%20one-informational.svg)](#license)

A lightweight Flask app for lawful research on Burner cloud artifacts. With a valid Firebase refresh token, you can mint an ID token, enumerate burners, list conversations, export messages, and perform controlled actions such as sending and per-conversation delete in a lab setting.

## Legal use

This project is for research only. Use only with accounts and devices you are authorized to access.

---
## BFCC Interface
![Burner Forensics Cloud Client Screenshot](https://anonymous.4open.science/r/BFCC-4F35/bfcc.drawio.png)

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Run options](#run-options)
- [Using the UI](#using-the-ui)
- [HTTP API](#http-api)
- [Schema examples](#schema-examples)
- [CLI and curl cookbook](#cli-and-curl-cookbook)
- [Evidence export workflow](#evidence-export-workflow)
- [Hashing and chain of custody](#hashing-and-chain-of-custody)
- [Troubleshooting](#troubleshooting)
- [Security hardening](#security-hardening)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Read-only Acquisition mode by default.** State-changing actions (send, delete) are
  refused with HTTP 403 and hidden/disabled in the UI unless the operator explicitly starts
  in Forensics mode (`BFCC_READONLY=0`).
- **Automatic evidence manifest on every export and bundle:** file SHA-256, per-item
  (per-conversation) SHA-256 digests, and a binary Merkle root over those digests, stamped
  with operator, case tag, mode, and UTC time — written to `<artifact>.manifest.json`.
- Exchange a Firebase refresh token for an ID token via Google Secure Token API
- Enumerate burners for a known user identifier
- List subscriptions, conversations, and SIP registration info
- Query messages by counterpart number in E.164 format
- Export complete message histories per number to one JSON file
- Save a bundle JSON of recent artifacts and selection state
- Controlled write actions (**Forensics mode only**):
  - Send message from selected burner
  - Delete conversation for a selected counterpart number
- Single-file UI using TailwindCSS and Alpine.js
- Data Console with pretty-printed JSON and download helpers

## Modes

BFCC starts in **Acquisition (read-only)** mode. The `/api/messages` (send) and
`/api/conversation-delete` endpoints return `403` in this mode, and the corresponding UI
controls are disabled. **Forensics mode** — which enables those write actions for lawfully
authorized investigative use — is opt-in and must be selected at startup:

```bash
BFCC_READONLY=0 python analysis.py     # Forensics mode (writes enabled)
python analysis.py                      # Acquisition mode (read-only, default)
```

The active mode is exposed at `GET /api/mode` and recorded in every evidence manifest.

---

## How it works

1. Paste a valid Firebase refresh token into the UI.  
2. Backend exchanges it at `securetoken.googleapis.com` to obtain an ID token.  
3. Requests to Phoenix API include `Authorization: Bearer <id_token>`.  
4. The app lists burners, conversations, and messages for `USER_ID`.  
5. You can export messages or save a bundle with recent responses.

Tokens are held only in memory for the Flask process lifetime by default.

---

## Project layout

```
.
├─ analysis.py   # Flask app with embedded Tailwind + Alpine UI
└─ README.md
```

---

## Prerequisites

- Python 3.10 or newer  
- A valid Firebase refresh token for a lab account you control

---

## Quick start

```bash
# 1) Create a virtual environment
python -m venv .venv

# 2) Activate it
# Windows PowerShell
. .venv/Scripts/Activate.ps1
# macOS or Linux
source .venv/bin/activate

# 3) Install deps
pip install flask requests

# 4) Run
python analysis.py

# 5) Open in browser
# http://127.0.0.1:8000
```

---

## Configuration

Edit the constants at the top of `app.py` or set environment variables.

```python
BASE_URL = "https://phoenix.burnerapp.com"
USER_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
DEFAULT_PAGE_SIZE = 50
TOKEN_URL = "https://securetoken.googleapis.com/v1/token?key=<firebase_web_api_key>"
```

**Environment variables**

PowerShell
```powershell
setx BFCC_USER_ID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
setx BFCC_FIREBASE_KEY "AIza...your_key..."
```

Bash
```bash
export BFCC_USER_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export BFCC_FIREBASE_KEY="AIza...your_key..."   # extracted from the target app at acquisition
export BFCC_READONLY=1                            # 1 = Acquisition (default), 0 = Forensics
export BFCC_OPERATOR="analyst-01"                 # stamped into evidence manifests
export BFCC_CASE="CASE-2026-0007"
```

`analysis.py` already reads all of these from the environment (`USER_ID`, `FIREBASE_KEY`,
`READ_ONLY`, `OPERATOR`, `CASE_TAG`). No secret is committed to the repo; supply the Firebase
key at runtime.

> Before publishing a repo, scrub any test keys or tokens from history.

---

## Run options

Local dev:
```bash
python app.py
# Serves http://127.0.0.1:8000 with debug=True
```

Disable debug for demos:
```python
# in app.py main guard
app.run(host="127.0.0.1", port=8000, debug=False)
```

Bind to all interfaces behind a reverse proxy:
```python
app.run(host="0.0.0.0", port=8000, debug=False)
```

---

## Using the UI

Open `http://127.0.0.1:8000`.

**Refresh Token**  
Paste refresh token, click Refresh. Auth badge turns green on success.

**Burners**  
Click Load, then click an item to select the active burner.

**Send SMS**  
Enter recipient in E.164 (example: `+12258025676`) and a short message. Click Send.

**Actions tab**
- Subscriptions: list active subscriptions  
- Conversations: populate `conversation_dict`  
- SIP Reg: fetch SIP registration record  
- Export All: serialize all conversations to server JSON with counts  
- Save Bundle: store one JSON with most recent artifacts

**Messages by Number tab**  
Choose a number from `conversation_dict`, set page and size, then Load Messages.  
Delete Conversation button appears after messages load.

**Data Console**  
Pretty JSON output for the selected action with Download JSON button and a link for server files.

---

## HTTP API

Headers: include `Authorization: Bearer <id_token>` for protected routes.

| Method | Path | Description |
|:------:|------|-------------|
| POST | `/api/refresh` | Exchange Firebase refresh token for ID token |
| GET | `/api/burners` | List burners for `USER_ID` |
| POST | `/api/select-burner` | Select burner by index from last burners result |
| GET | `/api/subscriptions` | List subscriptions |
| GET | `/api/conversations?page=1&pageSize=50` | List conversations and build `conversation_dict` |
| GET | `/api/conversation-messages?conversationId=+1...&page=1&pageSize=50` | Messages for counterpart number |
| POST | `/api/conversation-delete` | Delete conversation for counterpart number |
| GET | `/api/conversation-export?pageSize=100` | Export all histories to server file |
| GET | `/api/save-bundle` | Save bundle JSON with recent artifacts |
| GET | `/api/download?path=<abs_path>` | Download server file with safe path check |
| GET | `/api/sip-registration` | Retrieve SIP registration info |
| GET | `/api/mode` | Report current mode (Acquisition read-only vs Forensics) |

---

## Schema examples

**POST `/api/refresh` request**
```json
{ "refreshToken": "REFRESH_TOKEN_VALUE" }
```

**Success response**
```json
{
  "id_token": "eyJhbGciOi...",
  "raw": { "...": "full Secure Token API JSON" }
}
```

**GET `/api/conversations` response**
```json
{
  "conversations": [ { "conversation": { "conversationId": "+1..." } } ],
  "conversation_dict": { "0": "+1...", "1": "+1..." }
}
```

**GET `/api/conversation-messages` response**
```json
{
  "endpoint": "https://phoenix.../messages",
  "status": 200,
  "messages": [ { "text": "...", "timestamp": 1700000000, "direction": "outbound" } ]
}
```

**POST `/api/messages` request**
```json
{
  "burnerId": "burner-uuid",
  "conversationId": "+1XXXXXXXXXX",
  "text": "Hello from BFCC"
}
```

---

## CLI and curl cookbook

Replace placeholders with your values.

```bash
# 1. Refresh ID token
curl -s -X POST http://127.0.0.1:8000/api/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'

# 2. List burners
curl -s http://127.0.0.1:8000/api/burners \
  -H "Authorization: Bearer <ID_TOKEN>"

# 3. Select first burner
curl -s -X POST http://127.0.0.1:8000/api/select-burner \
  -H "Content-Type: application/json" \
  -d '{"index":0}'

# 4. List conversations
curl -s "http://127.0.0.1:8000/api/conversations?page=1&pageSize=50" \
  -H "Authorization: Bearer <ID_TOKEN>"

# 5. Messages for a number
curl -s "http://127.0.0.1:8000/api/conversation-messages?conversationId=+12223334444&page=1&pageSize=100" \
  -H "Authorization: Bearer <ID_TOKEN>"

# 6. Export all histories
curl -s "http://127.0.0.1:8000/api/conversation-export?pageSize=200" \
  -H "Authorization: Bearer <ID_TOKEN>"

# 7. Delete a conversation
curl -s -X POST http://127.0.0.1:8000/api/conversation-delete \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ID_TOKEN>" \
  -d '{"conversationId":"+12223334444"}'

# 8. Send a message
curl -s -X POST http://127.0.0.1:8000/api/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ID_TOKEN>" \
  -d '{"burnerId":"<BURNER_UUID>","conversationId":"+12223334444","text":"Hello from BFCC"}'

# 9. Download a server file (replace with an actual absolute path returned earlier)
curl -L -o export.json "http://127.0.0.1:8000/api/download?path=/absolute/path/to/file.json"
```

PowerShell hashing
```powershell
Get-FileHash .\conversation_full_history_*.json -Algorithm SHA256
Get-FileHash .\burner_bundle_*.json -Algorithm SHA256
```

macOS or Linux hashing
```bash
shasum -a 256 conversation_full_history_*.json
shasum -a 256 burner_bundle_*.json
```

---

## Evidence export workflow

1. Click Conversations to populate `conversation_dict`.  
2. Click Export All to paginate and aggregate messages for each counterpart number.  
3. The app writes one JSON with a map of number to list of messages.  
4. Use the link in the UI to download or fetch via `/api/download`.

Example structure
```json
{
  "+12223334444": [
    { "timestamp": 1700000000, "direction": "inbound", "text": "..." }
  ],
  "+15556667777": [
    { "timestamp": 1700001234, "direction": "outbound", "text": "..." }
  ]
}
```

---

## Hashing and chain of custody

Every export (`/api/conversation-export`) and bundle (`/api/save-bundle`) automatically
writes an evidence manifest to `<artifact>.manifest.json` containing:

- `filename`, `bytes`, and `sha256` of the artifact file
- `items[]` — per-conversation `{id, count, sha256}` digests (canonical JSON, sorted keys)
- `items_merkle_root` — a binary Merkle root over the per-item digests
- `created_utc`, `operator` (`BFCC_OPERATOR`), `case` (`BFCC_CASE`), `mode`, and `user_id`

Set the operator and case tag so they are stamped into the manifest:

```bash
BFCC_OPERATOR="analyst-01" BFCC_CASE="CASE-2026-0007" python analysis.py
```

Re-exports are new evidence objects with new hashes. Verify an artifact against its manifest
with any SHA-256 tool (`Get-FileHash` / `shasum -a 256`); the recorded `sha256` must match.

> Scope: the manifest supports integrity and reproducibility (read-only acquisition,
> per-item hashing, operator/case provenance). It is not, by itself, a claim of legal
> admissibility, which depends on jurisdiction and process.

---

## Troubleshooting

- **401 Authenticate first**  
  Refresh the token. ID token might be expired or missing.

- **403 Forbidden**  
  Token lacks permission for `USER_ID` or endpoint changed. Verify `USER_ID`, token scope, and base URL.

- **404 File not found on `/api/download`**  
  Path is missing or outside working directory. Use the exact path returned by export or bundle.

- **Messages empty while threads exist**  
  Server might have purged history or pagination is too small. Increase `pageSize` or iterate more pages.

- **Delete succeeded but content remains**  
  Some backends apply cleanup later. Reload messages to confirm.

- **Mixed content or CORS**  
  Keep same origin. If you add TLS or a reverse proxy, adjust headers accordingly.

---

## Security hardening

- Remove sample keys and tokens from history before publishing  
- Put `USER_ID` and Firebase key in env vars and CI secrets  
- Set `debug=False` outside local dev  
- Bind to `127.0.0.1` for local use or place behind a hardened reverse proxy  
- Add per-action audit logging with UTC timestamps and content redaction  
- Consider token lifetime limits and memory cleanup on logout  
- Pin dependency versions and patch regularly

---

## Roadmap

- Cryptographically *signed* evidence manifests (current manifests are hashed, not signed)  
- Timeline view with filtering and CSV export  
- Better rate limit handling and backoff  
- Headless CLI mode

---

## Contributing

Pull requests are welcome for:
- docs improvements  
- UI quality upgrades  
- safer export formats and hashing schemes  
- reproducible lab packaging

Please open an issue to discuss significant changes first.

---

## License

Choose a license that fits your goals. Common choices:
- MIT
- Apache 2.0
- BSD 3-Clause

Add a `LICENSE` file at the repo root.
