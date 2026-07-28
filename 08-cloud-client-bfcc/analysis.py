# app.py
import os
import json
import time
import hashlib
import pathlib
import requests
from datetime import datetime, timezone
from flask import Flask, request, render_template_string, jsonify, send_file, abort

# -------------------------
# CONFIG
# -------------------------
BASE_URL = "https://phoenix.burnerapp.com"
USER_ID = os.getenv("BFCC_USER_ID", "c2ce0c57-4***-40c1-b***-21******41b")  # device-associated userId, recovered by device acquisition
DEFAULT_PAGE_SIZE = 50

# Acquisition (read-only) mode is the default. Writes (send / delete) are refused
# unless the operator explicitly enables Forensics mode: BFCC_READONLY=0.
READ_ONLY = os.getenv("BFCC_READONLY", "1").strip().lower() not in ("0", "false", "no", "off")
# Chain-of-custody metadata stamped into every export manifest.
OPERATOR = os.getenv("BFCC_OPERATOR", "unspecified")
CASE_TAG = os.getenv("BFCC_CASE", "")

# Firebase Secure Token API (refresh -> id_token). Key must be supplied at runtime
# (extracted from the target app during device acquisition); never commit it.
FIREBASE_KEY = os.getenv("BFCC_FIREBASE_KEY", "REPLACE_ME")
TOKEN_URL = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_KEY}"
TOKEN_HEADERS = {
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; sdk_gphone64_x86_64 Build/SE1A.211212.001.B1)",
    "X-Android-Cert": "743C5F42F1C2300F4A41355276C5F8613B160932",
    "X-Android-Package": "com.adhoclabs.burner",
    "X-Client-Version": "Android/Fallback/X23000000/FirebaseCore-Android",
    "X-Firebase-GMPID": "1:84028889562:android:013a80e68c4bb7cc2c48e3",
}

# -------------------------
# Flask basics
# -------------------------
app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

# In-memory state (for demo). Use a DB/kv-store for production.
STATE = {
    "id_token": None,
    "selected_burner": None,       # { id, phoneNumber, ... }
    "conversation_dict": {},       # { idx: "+1..." }
    "last_artifacts": {}           # snapshots for bundling
}

# -------------------------
# Helpers
# -------------------------
def to_utc_str(epoch_any):
    if epoch_any is None:
        return ""
    try:
        ts = float(epoch_any)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(epoch_any)

def normalize_e164(s: str) -> str:
    s = (s or "").strip().replace(" ", "")
    if not s:
        return s
    if not s.startswith("+"):
        digits = "".join(ch for ch in s if ch.isdigit())
        if len(digits) == 10:
            return "+1" + digits
        return "+" + digits
    return s

def phoenix_headers(id_token: str) -> dict:
    return {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {id_token}",
        "Connection": "keep-alive",
        "Content-Type": "application/json; charset=utf-8",
        "DataStore-Control": "no-cache",
        "User-Agent": "Burner-Android",
        "X-ApplicationVersion": "5.13.0.2530.5929016",
    }

def burners_url() -> str:
    return f"{BASE_URL}/v3/user/{USER_ID}/burners"

def subscriptions_url() -> str:
    return f"{BASE_URL}/v3/user/{USER_ID}/subscriptions"

def conversations_url(page=1, pageSize=DEFAULT_PAGE_SIZE) -> str:
    return f"{BASE_URL}/v2/user/{USER_ID}/conversations?page={page}&pageSize={pageSize}"

def sip_registration_url() -> str:
    return f"{BASE_URL}/v2/user/{USER_ID}/sip-registration"

def messages_url(burner_id: str, conversation_id: str) -> str:
    return f"{BASE_URL}/v2/user/{USER_ID}/burners/{burner_id}/conversations/{conversation_id}/messages"

def safe_sendfile(path):
    base = pathlib.Path.cwd().resolve()
    p = pathlib.Path(path).resolve()
    if base not in p.parents and p != base:
        abort(400, "Invalid path")
    if not p.exists() or not p.is_file():
        abort(404, "File not found")
    return send_file(str(p), as_attachment=True)

def read_only_block():
    """Return a 403 response tuple if BFCC is in read-only Acquisition mode, else None."""
    if READ_ONLY:
        return jsonify({
            "error": "Read-only Acquisition mode: state-changing actions are disabled.",
            "hint": "Set BFCC_READONLY=0 to enable Forensics mode under documented lawful authority.",
        }), 403
    return None

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_canonical(obj) -> str:
    """Deterministic digest of a JSON-serializable object (sorted keys, no whitespace)."""
    return _sha256_hex(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

def _merkle_root(hexdigests):
    """Binary Merkle root over an ordered list of hex digests (odd nodes duplicated)."""
    if not hexdigests:
        return _sha256_hex(b"")
    layer = [bytes.fromhex(h) for h in hexdigests]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(hashlib.sha256(a + b).digest())
        layer = nxt
    return layer[0].hex()

def write_evidence_manifest(artifact_path: str, items: list, context: dict) -> dict:
    """
    Write a <artifact>.manifest.json next to an exported artifact.

    items: ordered [{"id": <str>, "count": <int>, "sha256": <hex>}, ...] per-item digests.
    Returns the manifest dict (also written to disk).
    """
    p = pathlib.Path(artifact_path)
    raw = p.read_bytes()
    manifest = {
        "tool": "BFCC",
        "schema": "bfcc-evidence-manifest/1",
        "artifact": str(p.resolve()),
        "filename": p.name,
        "bytes": len(raw),
        "sha256": _sha256_hex(raw),
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operator": OPERATOR,
        "case": CASE_TAG,
        "mode": "acquisition-read-only" if READ_ONLY else "forensics-writes-enabled",
        "user_id": USER_ID,
        "items": items,
        "items_merkle_root": _merkle_root([it["sha256"] for it in items]),
        **context,
    }
    mpath = str(p) + ".manifest.json"
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    manifest["manifest_path"] = os.path.abspath(mpath)
    return manifest

# -------------------------
# Backend endpoints (JSON)
# -------------------------
@app.post("/api/refresh")
def api_refresh():
    body = request.get_json(force=True) or {}
    refresh_token = body.get("refreshToken", "").strip()
    if not refresh_token:
        return jsonify({"error": "refreshToken is required"}), 400

    r = requests.post(
        TOKEN_URL,
        headers=TOKEN_HEADERS,
        data=json.dumps({"grantType": "refresh_token", "refreshToken": refresh_token}),
        timeout=(10, 60),
    )
    try:
        jd = r.json()
    except Exception:
        return jsonify({"error": r.text}), r.status_code

    id_token = jd.get("id_token")
    if not id_token:
        return jsonify({"error": "Could not obtain id_token", "raw": jd}), 400

    STATE["id_token"] = id_token
    return jsonify({"id_token": id_token, "raw": jd})

@app.get("/api/burners")
def api_burners():
    idt = STATE.get("id_token")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    r = requests.get(burners_url(), headers=phoenix_headers(idt), timeout=(10, 60))
    try:
        data = r.json()
    except Exception:
        data = r.text
    STATE["last_artifacts"]["burners"] = data
    return (jsonify(data), r.status_code)

@app.post("/api/select-burner")
def api_select_burner():
    body = request.get_json(force=True) or {}
    idx = body.get("index")
    burners = STATE.get("last_artifacts", {}).get("burners")
    if not isinstance(burners, list) or not burners:
        return jsonify({"error": "Load burners first."}), 400
    if isinstance(idx, int) and 0 <= idx < len(burners):
        STATE["selected_burner"] = burners[idx]
        return jsonify({"ok": True, "selected": STATE["selected_burner"]})
    return jsonify({"error": "Invalid index"}), 400

@app.get("/api/subscriptions")
def api_subscriptions():
    idt = STATE.get("id_token")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    r = requests.get(subscriptions_url(), headers=phoenix_headers(idt), timeout=(10, 60))
    try:
        data = r.json()
    except Exception:
        data = r.text
    STATE["last_artifacts"]["subscriptions"] = data
    return (jsonify(data), r.status_code)

@app.get("/api/conversations")
def api_conversations():
    idt = STATE.get("id_token")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401

    page = int(request.args.get("page", "1"))
    page_size = int(request.args.get("pageSize", str(DEFAULT_PAGE_SIZE)))
    r = requests.get(conversations_url(page, page_size), headers=phoenix_headers(idt), timeout=(10, 60))
    try:
        data = r.json()
    except Exception:
        data = r.text

    STATE["last_artifacts"]["conversations"] = data

    # Build and store conversation_dict { idx: conversationId }
    convo_dict = {}
    if isinstance(data, list):
        for idx, item in enumerate(data):
            conv = item.get("conversation", {}) or {}
            conv_id = conv.get("conversationId")
            if conv_id:
                convo_dict[idx] = conv_id
    STATE["conversation_dict"] = convo_dict

    return jsonify({"conversations": data, "conversation_dict": convo_dict}), r.status_code

@app.get("/api/conversation-messages")
def api_conversation_messages():
    """
    Fetch messages for a single conversationId (E.164 number) using the currently selected burner.
    Query params: conversationId=+1..., page=1, pageSize=50
    """
    idt = STATE.get("id_token")
    sb = STATE.get("selected_burner")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    if not sb:
        return jsonify({"error": "Select a burner first."}), 400

    conversation_id = normalize_e164(request.args.get("conversationId", ""))
    if not conversation_id:
        return jsonify({"error": "conversationId is required"}), 400

    page = int(request.args.get("page", "1"))
    page_size = int(request.args.get("pageSize", str(DEFAULT_PAGE_SIZE)))

    url = messages_url(sb["id"], conversation_id)
    r = requests.get(url, params={"page": page, "pageSize": page_size}, headers=phoenix_headers(idt), timeout=(10, 60))
    try:
        data = r.json()
    except Exception:
        data = r.text

    return jsonify({"endpoint": url, "status": r.status_code, "messages": data})

@app.post("/api/conversation-delete")
def api_conversation_delete():
    """
    Delete all messages for a single conversationId using the selected burner.
    JSON body: { "conversationId": "+1..." }
    """
    blocked = read_only_block()
    if blocked:
        return blocked
    idt = STATE.get("id_token")
    sb = STATE.get("selected_burner")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    if not sb:
        return jsonify({"error": "Select a burner first."}), 400

    body = request.get_json(force=True) or {}
    conversation_id = normalize_e164(body.get("conversationId") or "")
    if not conversation_id:
        return jsonify({"error": "conversationId is required"}), 400

    url = messages_url(sb["id"], conversation_id)
    r = requests.delete(url, headers=phoenix_headers(idt), timeout=(10, 60))
    try:
        payload = r.json()
    except Exception:
        payload = r.text

    # Optionally update in-memory conversation_dict if the API actually removes it server-side.
    # We don't assume; we just return the result.
    return jsonify({"endpoint": url, "status": r.status_code, "body": payload})

@app.get("/api/conversation-export")
def api_conversation_export():
    idt = STATE.get("id_token")
    sb = STATE.get("selected_burner")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    if not sb:
        return jsonify({"error": "Select a burner first."}), 400

    convo_dict = STATE.get("conversation_dict") or {}
    if not convo_dict:
        r = requests.get(conversations_url(1, DEFAULT_PAGE_SIZE), headers=phoenix_headers(idt), timeout=(10, 60))
        try:
            data = r.json()
        except Exception:
            return jsonify({"error": "Failed to load conversations", "raw": r.text}), 502
        tmp = {}
        if isinstance(data, list):
            for idx, item in enumerate(data):
                conv = item.get("conversation", {}) or {}
                cid = conv.get("conversationId")
                if cid:
                    tmp[idx] = cid
        STATE["conversation_dict"] = tmp
        convo_dict = tmp

    page_size = int(request.args.get("pageSize", "100"))
    burner_id = sb["id"]

    def fetch_all_for(conversation_id: str):
        url = messages_url(burner_id, conversation_id)
        collected = []
        page = 1
        while True:
            r = requests.get(url, params={"page": page, "pageSize": page_size}, headers=phoenix_headers(idt), timeout=(10, 60))
            try:
                payload = r.json()
            except Exception:
                break
            if not isinstance(payload, list):
                break
            collected.extend(payload)
            if len(payload) < page_size:
                break
            page += 1
        return collected

    full = {}
    for _, conv_id in sorted(convo_dict.items()):
        full[conv_id] = fetch_all_for(conv_id)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fname = f"conversation_full_history_{USER_ID}_{burner_id}_{ts}.json"
    path = os.path.abspath(fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(full, f, ensure_ascii=False, indent=2)

    # Per-item (per-conversation) digests + evidence manifest with a Merkle root.
    items = [
        {"id": conv_id, "count": len(msgs), "sha256": _sha256_canonical(msgs)}
        for conv_id, msgs in sorted(full.items())
    ]
    manifest = write_evidence_manifest(
        path, items,
        {"artifact_type": "conversation_full_history", "burner_id": burner_id},
    )

    STATE["last_artifacts"]["conversation_full_history_path"] = path
    STATE["last_artifacts"]["conversation_full_history_manifest"] = manifest["manifest_path"]
    summary = {k: len(v) for k, v in full.items()}
    return jsonify({
        "saved_file": path,
        "manifest_file": manifest["manifest_path"],
        "sha256": manifest["sha256"],
        "items_merkle_root": manifest["items_merkle_root"],
        "counts_by_conversationId": summary,
        "conversation_dict": convo_dict
    })

@app.get("/api/save-bundle")
def api_save_bundle():
    artifacts = {
        "selectedBurner": STATE.get("selected_burner"),
        "conversation_dict": STATE.get("conversation_dict"),
        **STATE.get("last_artifacts", {}),
    }
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(f"burner_bundle_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(artifacts, f, ensure_ascii=False, indent=2)

    items = [
        {"id": k, "count": (len(v) if isinstance(v, (list, dict)) else 1), "sha256": _sha256_canonical(v)}
        for k, v in sorted(artifacts.items(), key=lambda kv: kv[0])
    ]
    manifest = write_evidence_manifest(path, items, {"artifact_type": "bundle"})
    return jsonify({"paths": {"bundle_json": path, "manifest_json": manifest["manifest_path"]},
                    "sha256": manifest["sha256"],
                    "items_merkle_root": manifest["items_merkle_root"]})

@app.get("/api/download")
def api_download():
    path = request.args.get("path")
    if not path:
        abort(400, "path required")
    return safe_sendfile(path)

@app.get("/api/mode")
def api_mode():
    return jsonify({
        "read_only": READ_ONLY,
        "mode": "Acquisition (read-only)" if READ_ONLY else "Forensics (writes enabled)",
        "operator": OPERATOR,
        "case": CASE_TAG,
    })

@app.get("/api/sip-registration")
def api_sip():
    idt = STATE.get("id_token")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    r = requests.get(sip_registration_url(), headers=phoenix_headers(idt), timeout=(10, 60))
    try:
        data = r.json()
    except Exception:
        data = r.text
    STATE["last_artifacts"]["sipRegistration"] = data
    return (jsonify(data), r.status_code)

@app.post("/api/messages")
def api_send():
    blocked = read_only_block()
    if blocked:
        return blocked
    idt = STATE.get("id_token")
    if not idt:
        return jsonify({"error": "Authenticate first (no id_token)."}), 401
    body = request.get_json(force=True) or {}
    burner_id = (body.get("burnerId") or (STATE.get("selected_burner") or {}).get("id") or "").strip()
    conversation_id = normalize_e164(body.get("conversationId") or "")
    text = (body.get("text") or "").strip()
    if not burner_id or not conversation_id or not text:
        return jsonify({"error": "burnerId, conversationId and text are required"}), 400
    r = requests.post(
        messages_url(burner_id, conversation_id),
        headers=phoenix_headers(idt),
        json={"text": text},
        timeout=(10, 60),
    )
    try:
        data = r.json()
    except Exception:
        data = r.text
    return (jsonify({"status": r.status_code, "body": data}), r.status_code)

# -------------------------
# UI (Jinja + Tailwind)
# -------------------------
TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>BFCC — Burner Forensics Cloud Client</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
  <script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
</head>
<body class="min-h-screen bg-slate-50 text-slate-900">
  <div class="mx-auto max-w-6xl px-6 pt-8 pb-4">
    <div class="flex flex-col items-center gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div class="text-center sm:text-left">
        <h1 class="text-2xl md:text-3xl font-semibold tracking-tight">Burner Forensics Cloud Client</h1>
        <p class="text-sm text-slate-600 mt-1">Cloud artifact acquisition, conversation mapping, and message export.</p>
      </div>
      <div class="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs"
           :class="idToken ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-white text-slate-700 border-slate-200'">
        <span class="inline-block h-2 w-2 rounded-full" :class="idToken ? 'bg-emerald-500' : 'bg-slate-400'"></span>
        <span x-text="idToken ? 'Authenticated' : 'Not authenticated'"></span>
      </div>
    </div>
  </div>

  <main x-data="app()" class="mx-auto max-w-6xl px-6 pb-16">
    <!-- Mode banner -->
    <div class="mb-4 flex items-center gap-2">
      <span class="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium"
            :class="readOnly ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-rose-50 text-rose-700 border-rose-200'">
        <span class="inline-block h-2 w-2 rounded-full" :class="readOnly ? 'bg-amber-500' : 'bg-rose-500'"></span>
        <span x-text="readOnly ? 'Acquisition mode — read-only (writes disabled)' : 'Forensics mode — writes enabled'"></span>
      </span>
      <span class="text-xs text-slate-500" x-show="readOnly">Send / Delete are disabled. Start with BFCC_READONLY=0 to enable.</span>
    </div>

    <!-- Top: Three Card Flow -->
    <section class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Card 1: Refresh -->
      <div class="rounded-2xl shadow-sm border border-slate-200 bg-white">
        <div class="px-5 py-3 border-b border-slate-100">
          <h3 class="text-lg font-semibold">Refresh Token</h3>
        </div>
        <div class="p-5 space-y-3">
          <label class="text-sm font-medium text-slate-700" for="rt">Firebase refresh token</label>
          <textarea id="rt" rows="4"
            class="w-full rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-4 focus:ring-blue-100"
            placeholder="Paste refresh token…" x-model="refreshToken"></textarea>
          <button @click="doRefresh" :disabled="busy"
            class="w-full h-11 rounded-xl font-medium shadow-sm bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">
            Refresh
          </button>
        </div>
      </div>

      <!-- Card 2: Burners -->
      <div class="rounded-2xl shadow-sm border border-slate-200 bg-white">
        <div class="px-5 py-3 border-b border-slate-100">
          <h3 class="text-lg font-semibold">Burners</h3>
        </div>
        <div class="p-5 space-y-3">
          <button @click="loadBurners" :disabled="!idToken || busy"
            class="w-full h-11 rounded-xl font-medium shadow-sm bg-slate-900 text-white hover:bg-black disabled:opacity-50">
            Load
          </button>

          <template x-if="burners.length === 0">
            <p class="text-sm text-slate-600">No burners yet.</p>
          </template>

          <div class="space-y-2" x-show="burners.length">
            <template x-for="(b, idx) in burners" :key="b.id">
              <button @click="selectIndex(idx)"
                class="w-full text-left rounded-xl border px-3 py-2"
                :class="selectedIndex===idx ? 'border-blue-300 bg-blue-50' : 'border-slate-200 bg-white'">
                <div class="font-medium" x-text="b.phoneNumber"></div>
                <div class="text-xs text-slate-500" x-text="'id=' + b.id"></div>
                <div class="text-xs text-slate-500" x-text="'created=' + fmt(b.dateCreated) + ' · expires=' + fmt(b.expirationDate)"></div>
              </button>
            </template>
          </div>
        </div>
      </div>

      <!-- Card 3: Send SMS -->
      <div class="rounded-2xl shadow-sm border border-slate-200 bg-white">
        <div class="px-5 py-3 border-b border-slate-100">
          <h3 class="text-lg font-semibold">Send SMS</h3>
        </div>
        <div class="p-5 space-y-3">
          <div class="text-sm text-slate-600">
            Using: <span class="font-medium" x-text="selectedBurner ? selectedBurner.phoneNumber : '—'"></span>
          </div>
          <input id="recipient" x-model="recipient" placeholder="Recipient (E.164, e.g., +12258025676)"
                 class="w-full rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-4 focus:ring-blue-100"/>
          <textarea id="message" rows="3" x-model="message" placeholder="Message…"
                    class="w-full rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-4 focus:ring-blue-100"></textarea>
          <button @click="doSend" :disabled="!idToken || selectedIndex===null || busy || readOnly"
            class="w-full h-11 rounded-xl font-medium shadow-sm bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-50">
            <span x-text="readOnly ? 'Send (disabled in Acquisition mode)' : 'Send'"></span>
          </button>
        </div>
      </div>
    </section>

    <!-- Tabbed Section: Actions | Messages by Number -->
    <section class="mt-8 rounded-2xl border border-slate-200 bg-white shadow-sm">
      <!-- Tabs -->
      <div class="flex items-center gap-2 px-5 pt-4 border-b border-slate-100">
        <button @click="activeTab='actions'"
                :class="activeTab==='actions' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'"
                class="h-9 px-3 rounded-lg text-sm font-medium">Actions</button>
        <button @click="activeTab='perNumber'"
                :class="activeTab==='perNumber' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'"
                class="h-9 px-3 rounded-lg text-sm font-medium">Messages by Number</button>
      </div>

      <!-- Tab Panels -->
      <div class="p-5">
        <!-- Actions Panel -->
        <div x-show="activeTab==='actions'" x-cloak>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <button @click="runAndShow('Subscriptions', loadSubscriptions)" :disabled="!idToken || busy"
              class="h-11 w-full rounded-xl font-medium shadow-sm bg-slate-800 text-white hover:bg-slate-900 disabled:opacity-50">
              Subscriptions
            </button>
            <button @click="runAndShow('Conversations', loadConversations)" :disabled="!idToken || busy"
              class="h-11 w-full rounded-xl font-medium shadow-sm bg-slate-800 text-white hover:bg-slate-900 disabled:opacity-50">
              Conversations
            </button>
            <button @click="runAndShow('SIP Registration', loadSip)" :disabled="!idToken || busy"
              class="h-11 w-full rounded-xl font-medium shadow-sm bg-slate-800 text-white hover:bg-slate-900 disabled:opacity-50">
              SIP Reg
            </button>
            <button @click="runAndShow('Export Summary', exportConversations)" :disabled="!idToken || selectedIndex===null || busy"
              class="h-11 w-full rounded-xl font-medium shadow-sm bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">
              Export All
            </button>
            <button @click="runAndShow('Bundle Paths', saveBundle)" :disabled="!idToken || busy"
              class="h-11 w-full rounded-xl font-medium shadow-sm bg-slate-700 text-white hover:bg-slate-800 disabled:opacity-50">
              Save Bundle
            </button>
          </div>
        </div>

        <!-- Per-Number Panel -->
        <div x-show="activeTab==='perNumber'" x-cloak>
          <div class="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
            <div class="md:col-span-2">
              <label class="text-sm font-medium text-slate-700">Select number (from conversation_dict)</label>
              <select x-model="selectedConvId"
                      class="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-4 focus:ring-blue-100">
                <option value="" disabled>Select…</option>
                <template x-if="!conversationDict">
                  <option value="">(Load Conversations first)</option>
                </template>
                <template x-if="conversationDict">
                  <template x-for="(num, idx) in conversationDict" :key="idx">
                    <option :value="num" x-text="num"></option>
                  </template>
                </template>
              </select>
              <p class="text-xs text-slate-500 mt-1">Tip: Click <strong>Conversations</strong> in Actions to populate this list.</p>
            </div>
            <div>
              <label class="text-sm font-medium text-slate-700">Page</label>
              <input type="number" min="1" x-model.number="perNumberPage"
                     class="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-4 focus:ring-blue-100" />
            </div>
            <div>
              <label class="text-sm font-medium text-slate-700">Page size</label>
              <input type="number" min="1" x-model.number="perNumberPageSize"
                     class="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2 focus:outline-none focus:ring-4 focus:ring-blue-100" />
            </div>
          </div>

          <div class="mt-3 flex items-center gap-3">
            <button @click="runAndShow('Messages: '+(selectedConvId||'—'), loadMessagesByNumber)"
                    :disabled="!idToken || !selectedBurner || !selectedConvId || busy"
                    class="h-11 rounded-xl px-4 font-medium shadow-sm bg-slate-900 text-white hover:bg-black disabled:opacity-50">
              Load Messages
            </button>

            <!-- Delete button appears after messages are loaded (Forensics mode only) -->
            <template x-if="!readOnly && activeViewName && activeViewName.startsWith('Messages:') && activeData && selectedConvId">
              <button @click="confirmAndDelete()"
                      class="h-11 rounded-xl px-4 font-medium shadow-sm bg-rose-600 text-white hover:bg-rose-700">
                Delete Conversation
              </button>
            </template>
          </div>
        </div>

        <!-- Data Console (shared) -->
        <div class="mt-6">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-xs uppercase tracking-wide text-slate-500">Data Console</div>
              <div class="text-base font-semibold" x-text="activeViewName || '—'"></div>
            </div>
            <div class="flex items-center gap-2">
              <template x-if="activeData">
                <button @click="downloadJSON(activeViewName || 'data', activeData)"
                        class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm hover:bg-slate-50">
                  Download JSON
                </button>
              </template>
              <template x-if="activeServerFile">
                <a :href="'/api/download?path=' + encodeURIComponent(activeServerFile)"
                   class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm hover:bg-slate-50">
                  Download from Server
                </a>
              </template>
              <button @click="clearConsole"
                      class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 hover:bg-rose-100">
                Clear
              </button>
            </div>
          </div>

          <div class="mt-3">
            <template x-if="!activeData && !activeServerFile">
              <div class="text-sm text-slate-500">Nothing loaded yet. Use the tabs above.</div>
            </template>
            <template x-if="activeData">
              <pre class="max-h-[28rem] overflow-auto rounded-xl bg-slate-50 p-3 border text-[12px]" x-text="pretty(activeData)"></pre>
            </template>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Toast -->
  <div x-show="toast" x-transition
       class="fixed bottom-6 left-1/2 -translate-x-1/2 rounded-xl bg-slate-900 text-white px-4 py-2 shadow-lg"
       x-text="toast"></div>

  <script>
    function app(){
      return {
        // state
        refreshToken: "",
        idToken: null,
        burners: [],
        selectedIndex: null,
        recipient: "",
        message: "",
        subscriptions: null,
        conversations: null,
        conversationDict: null,
        sip: null,
        exportSummary: null,
        bundlePaths: null,

        // per-number tab state
        activeTab: 'actions',
        selectedConvId: "",
        perNumberPage: 1,
        perNumberPageSize: 50,

        busy: false,
        toast: null,
        readOnly: true,   // default until /api/mode confirms

        // console
        activeViewName: null,
        activeData: null,
        activeServerFile: null,

        // lifecycle
        async init(){
          try {
            const r = await fetch('/api/mode');
            const d = await r.json();
            this.readOnly = !!d.read_only;
          } catch(e){ /* keep read-only default */ }
        },

        // helpers
        note(msg){ this.toast = msg; setTimeout(()=>this.toast=null, 2500); },
        pretty(o){ try { return JSON.stringify(o, null, 2); } catch(e){ return String(o); } },
        fmt(e){ if(e==null) return ""; let ts = Number(e); if(ts>1e12) ts/=1000; return new Date(ts*1000).toISOString().replace('.000Z','Z'); },
        downloadJSON(name, obj){
          try{
            const blob = new Blob([JSON.stringify(obj, null, 2)], {type: 'application/json'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = (name || 'data').toLowerCase().replace(/\\s+/g,'_') + '.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
          }catch(e){ this.note('Download failed'); }
        },
        clearConsole(){
          this.activeViewName = null;
          this.activeData = null;
          this.activeServerFile = null;
        },
        async runAndShow(label, fn){
          this.activeViewName = label;
          this.activeData = null;
          this.activeServerFile = null;
          await fn.call(this);
          if(label === 'Subscriptions') this.activeData = this.subscriptions;
          if(label === 'Conversations') this.activeData = { conversations: this.conversations, conversation_dict: this.conversationDict };
          if(label === 'SIP Registration') this.activeData = this.sip;
          if(label === 'Export Summary'){
            this.activeData = this.exportSummary ? this.exportSummary.counts_by_conversationId : null;
            this.activeServerFile = this.exportSummary?.saved_file || null;
          }
          if(label === 'Bundle Paths') this.activeData = { paths: this.bundlePaths || null };
          if(label.startsWith('Messages:')){
            // activeData already set in loadMessagesByNumber
          }
        },

        // auth
        async doRefresh(){
          if(!this.refreshToken.trim()) return this.note("Paste a refresh token first.");
          this.busy = true;
          try{
            const res = await fetch('/api/refresh', {
              method:'POST', headers:{'Content-Type':'application/json'},
              body: JSON.stringify({ refreshToken: this.refreshToken })
            });
            const jd = await res.json();
            if(!res.ok) throw new Error(jd.error || 'refresh failed');
            this.idToken = jd.id_token || jd.idToken || null;
            this.note('Token refreshed.');
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },

        // burners
        async loadBurners(){
          if(!this.idToken) return this.note('Authenticate first.');
          this.busy = true;
          try{
            const res = await fetch('/api/burners', { headers:{ Authorization: 'Bearer '+this.idToken }});
            const data = await res.json();
            if(!res.ok) throw new Error(data.error || 'burners failed');
            this.burners = Array.isArray(data) ? data : [];
            this.selectedIndex = this.burners.length ? 0 : null;
            if(this.selectedIndex !== null){
              await fetch('/api/select-burner', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({index:this.selectedIndex})});
            }
            this.note('Burners loaded.');
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },
        async selectIndex(idx){
          this.selectedIndex = idx;
          await fetch('/api/select-burner', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({index:idx})});
        },
        get selectedBurner(){ return (this.selectedIndex===null) ? null : this.burners[this.selectedIndex] || null; },

        // loaders
        async loadSubscriptions(){
          this.busy = true;
          try{
            const r = await fetch('/api/subscriptions', { headers:{ Authorization:'Bearer '+this.idToken }});
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'subs failed');
            this.subscriptions = d;
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },
        async loadConversations(){
          this.busy = true;
          try{
            const r = await fetch('/api/conversations?page=1&pageSize=50', { headers:{ Authorization:'Bearer '+this.idToken }});
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'conversations failed');
            this.conversations = d.conversations || d;
            this.conversationDict = d.conversation_dict || null;
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },
        async loadSip(){
          this.busy = true;
          try{
            const r = await fetch('/api/sip-registration', { headers:{ Authorization:'Bearer '+this.idToken }});
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'sip failed');
            this.sip = d;
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },
        async exportConversations(){
          if(!this.selectedBurner) return this.note('Pick a burner first.');
          this.busy = true;
          try{
            if(!this.conversationDict){ await this.loadConversations(); }
            const r = await fetch('/api/conversation-export', { headers:{ Authorization:'Bearer '+this.idToken }});
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'export failed');
            this.exportSummary = d;
            this.note('Export complete.');
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },
        async saveBundle(){
          this.busy = true;
          try{
            const r = await fetch('/api/save-bundle', { headers:{ Authorization:'Bearer '+this.idToken }});
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'save failed');
            this.bundlePaths = d?.paths || null;
            this.note('Bundle saved.');
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },

        // per-number loader
        async loadMessagesByNumber(){
          if(!this.selectedBurner) return this.note('Pick a burner first.');
          if(!this.selectedConvId) return this.note('Select a number.');
          this.busy = true;
          try{
            if(!this.conversationDict){ await this.loadConversations(); }
            const params = new URLSearchParams({
              conversationId: this.selectedConvId,
              page: String(this.perNumberPage || 1),
              pageSize: String(this.perNumberPageSize || 50)
            }).toString();
            const r = await fetch('/api/conversation-messages?'+params, { headers:{ Authorization:'Bearer '+this.idToken }});
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'messages failed');
            this.activeData = d;              // show full payload
            this.activeServerFile = null;
            this.activeViewName = 'Messages: ' + this.selectedConvId;
            this.note('Messages loaded.');
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },

        // delete flow
        async confirmAndDelete(){
          if(this.readOnly) return this.note('Disabled in Acquisition (read-only) mode.');
          if(!this.selectedConvId) return;
          const ok = window.confirm('This will delete the entire conversation for '+ this.selectedConvId + '. Proceed?');
          if(!ok) return;
          this.busy = true;
          try{
            const r = await fetch('/api/conversation-delete', {
              method:'POST',
              headers:{ 'Content-Type':'application/json', Authorization:'Bearer '+this.idToken },
              body: JSON.stringify({ conversationId: this.selectedConvId })
            });
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'delete failed');
            this.note('Conversation deleted.');
            // Clear console and remove from local conversationDict dropdown (if present)
            this.clearConsole();
            if(this.conversationDict){
              // conversationDict is an object like { "0": "+1...", "1": "+1..." }
              const newDict = {};
              Object.entries(this.conversationDict).forEach(([k,v])=>{
                if(v !== this.selectedConvId) newDict[k] = v;
              });
              this.conversationDict = newDict;
            }
            this.selectedConvId = "";
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        },

        // send
        async doSend(){
          if(this.readOnly) return this.note('Disabled in Acquisition (read-only) mode.');
          if(!this.selectedBurner) return this.note('Pick a burner.');
          if(!this.recipient.trim()) return this.note('Enter recipient.');
          if(!this.message.trim()) return this.note('Enter message.');
          this.busy = true;
          try{
            const r = await fetch('/api/messages', {
              method:'POST',
              headers:{ 'Content-Type':'application/json', Authorization:'Bearer '+this.idToken },
              body: JSON.stringify({ burnerId: this.selectedBurner.id, conversationId: this.recipient.trim(), text: this.message.trim() })
            });
            const d = await r.json();
            if(!r.ok) throw new Error(d.error || 'send failed');
            this.note('Sent.');
          } catch(e){ this.note(e.message || e); }
          finally { this.busy = false; }
        }
      }
    }
  </script>
</body>
</html>
"""

@app.get("/")
def index():
    return render_template_string(TEMPLATE)

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
