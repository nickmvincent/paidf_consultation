import io
import json
import re
import secrets
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse


# ---------------------------
# Config / Constants
# ---------------------------
DB_PATH = str(Path.home() / ".open-webui" / "webui.db")
DEFAULT_DATASET_REPO = "publicai/shared-chats"

HUGGINGFACE_TOKENS_DOC_URL = "https://huggingface.co/docs/hub/en/security-tokens"
HUGGINGFACE_TOKENS_SETTINGS_URL = "https://huggingface.co/settings/tokens"
HUGGINGFACE_DATASET_DISCUSSION_URL = (
    "https://huggingface.co/datasets/{repo}/discussions/{num}"
)

PRIVACY_PATTERNS = {
    "email": (
        r"(?<![A-Za-z0-9._%+-])"
        r"[A-Za-z0-9](?:[A-Za-z0-9_%+\-]*[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9_%+\-]*[A-Za-z0-9])?)*"
        r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
        r"(?![A-Za-z0-9._%+-])"
    ),
    "phone_us": r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
    "credit_card": r"\b(?:\d[-\s]?){13,19}\b",
}


app = FastAPI()


# ---------------------------
# Helpers
# ---------------------------
def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def check_privacy(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for msg in messages:
        text = msg.get("content") or ""
        if not text:
            continue
        for name, pat in PRIVACY_PATTERNS.items():
            matches = re.findall(pat, text, flags=re.IGNORECASE)
            if not matches:
                continue
            if name == "credit_card":
                good = [m for m in matches if luhn_ok(m)]
                if not good:
                    continue
                counts[name] = counts.get(name, 0) + len(good)
            else:
                counts[name] = counts.get(name, 0) + len(matches)
    return {
        "has_issues": bool(counts),
        "types_found": sorted([k for k, v in counts.items() if v > 0]),
        "counts": counts,
        "note": "Heuristic only; review before sharing.",
    }


def clean_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for m in messages:
        if not (isinstance(m, dict) and "role" in m and "content" in m):
            continue
        keep = {"role": m.get("role"), "content": m.get("content")}
        if "id" in m:
            keep["id"] = m["id"]
        if "model" in m:
            keep["model"] = m["model"]
        if "tool_calls" in m:
            keep["tool_calls"] = m["tool_calls"]
        out.append(keep)
    return out


def hash_messages(messages: List[Dict[str, Any]]) -> str:
    digest_basis = []
    for m in messages:
        digest_basis.append(
            {
                "role": m.get("role"),
                "content": m.get("content"),
                "model": m.get("model"),
                "tool_calls": m.get("tool_calls"),
            }
        )
    content = json.dumps(digest_basis, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def get_full_chat(chat_id: str) -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM chat WHERE id = ?", (chat_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError("Chat not found")
    row = dict(row)

    # tags
    cur.execute("SELECT tag_name FROM chatidtag WHERE chat_id = ?", (chat_id,))
    tag_rows = [r["tag_name"] for r in cur.fetchall() if r and r["tag_name"]]

    # payload
    chat_json = {}
    if isinstance(row.get("chat"), str):
        try:
            chat_json = json.loads(row.get("chat") or "{}")
        except Exception:
            chat_json = {}
    elif isinstance(row.get("chat"), dict):
        chat_json = row.get("chat") or {}
    messages = chat_json.get("messages", []) if isinstance(chat_json, dict) else []
    payload_tags = chat_json.get("tags", []) if isinstance(chat_json, dict) else []

    # feedbacks by chat id
    q = """
        SELECT id, type, data, meta, created_at
        FROM feedback
        WHERE COALESCE(
            json_extract(meta, '$.chat_id'),
            json_extract(data, '$.chat_id'),
            json_extract(meta, '$.chatId'),
            json_extract(data, '$.chatId')
        ) = ?
        ORDER BY created_at DESC
    """
    cur.execute(q, (chat_id,))
    rows = cur.fetchall()
    items: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        for k in ("data", "meta"):
            if isinstance(d.get(k), str):
                try:
                    d[k] = json.loads(d[k])
                except Exception:
                    pass
        items.append(d)

    def to_num(x):
        try:
            return int(x)
        except Exception:
            try:
                return float(x)
            except Exception:
                return None

    def is_good(it):
        t = (it.get("type") or "").lower()
        if t in ("good", "good_response", "thumbs_up"):
            return True
        n = to_num((it.get("data") or {}).get("rating"))
        if n is not None:
            return n > 0
        r = str((it.get("data") or {}).get("rating", "")).lower()
        return r in ("good", "thumbs_up", "up", "1", "+1", "positive")

    def is_bad(it):
        t = (it.get("type") or "").lower()
        if t in ("bad", "bad_response", "thumbs_down"):
            return True
        n = to_num((it.get("data") or {}).get("rating"))
        if n is not None:
            return n < 0
        r = str((it.get("data") or {}).get("rating", "")).lower()
        return r in ("bad", "thumbs_down", "down", "-1", "negative")

    good = sum(1 for it in items if is_good(it))
    bad = sum(1 for it in items if is_bad(it))

    conn.close()
    return {
        "chat_id": chat_id,
        "title": row.get("title", "Untitled Chat"),
        "messages": messages,
        "tags": list({*(tag_rows or []), *(payload_tags or [])}),
        "feedback_items": items,
        "feedback_counts": {"good": good, "bad": bad},
    }


def compute_reason(counts: Dict[str, int]) -> Tuple[str, str]:
    g, b = counts.get("good", 0), counts.get("bad", 0)
    if g > b:
        return "dataset-good", "good"
    if b > g:
        return "dataset-bad", "bad"
    return "dataset-mixed", "mixed"


def create_pr(contribution: Dict[str, Any], hf_token: str, dataset_repo: str) -> Dict[str, Any]:
    try:
        from huggingface_hub import HfApi, CommitOperationAdd  # type: ignore
        api = HfApi()
        file_path = f"contributions/{contribution['id']}.json"
        content = json.dumps(contribution, ensure_ascii=False, indent=2)
        commit_info = api.create_commit(
            repo_id=dataset_repo,
            operations=[CommitOperationAdd(path_in_repo=file_path, path_or_fileobj=io.BytesIO(content.encode()))],
            commit_message=f"[{contribution['sharing_reason']}] Contribution ({contribution.get('attribution', 'anonymous')})",
            commit_description=f"Content Hash: {contribution.get('content_hash','N/A')}",
            token=hf_token,
            create_pr=True,
            repo_type="dataset",
        )
        pr_num = getattr(commit_info, "pr_num", None)
        pr_url = (
            HUGGINGFACE_DATASET_DISCUSSION_URL.format(repo=dataset_repo, num=pr_num)
            if pr_num
            else getattr(commit_info, "pr_url", "Check repository")
        )
        return {"success": True, "pr_number": pr_num, "pr_url": pr_url}
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}


# ---------------------------
# UI
# ---------------------------
def page(title: str, body: str) -> HTMLResponse:
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 1rem; color: #111; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    .warning {{ background: #fff7ed; border: 1px solid #fed7aa; padding: 12px; border-radius: 6px; }}
    .muted {{ color: #6b7280; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    label {{ display:block; font-size: 12px; color: #374151; margin-bottom: 4px; }}
    input, select, textarea {{ width: 100%; box-sizing: border-box; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px; }}
    button {{ background:#111827; color:#fff; border:0; border-radius:6px; padding:10px 14px; cursor:pointer; }}
    code, pre {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 8px; overflow: auto; }}
  </style>
</head>
<body>
  <div class=container>
    {body}
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html, headers={"Content-Disposition": "inline"})


@app.get("/flywheel/prepare")
def prepare(request: Request, chat_id: str = "", attribution_mode: str = "anonymous", license_intent: str = "AI devs who contribute back to the ecosystem", license_intent_note: str = "", ai_thoughts: str = ""):
    if not chat_id:
        return page("Flywheel — Setup", "<div class='card'><strong>Error:</strong> chat_id is required. Open this from the tool to auto-fill it.</div>")
    try:
        chat = get_full_chat(chat_id)
        clean = clean_messages(chat["messages"])
        privacy = check_privacy(clean)
        sharing_tag, reason = compute_reason(chat["feedback_counts"])
        preview = {
            "title": chat["title"],
            "messages": len(clean),
            "tags": chat["tags"],
            "feedback": chat["feedback_counts"],
            "assessment": reason,
            "sharing_tag": sharing_tag,
        }
        body = f"""
<div class='card warning'><strong>⚠️ Public Share</strong> Review carefully before submitting.</div>

<div class='card'>
  <h3 style='margin-top:0'>Contribution Preview</h3>
  <div><strong>Title</strong>: {preview['title']}</div>
  <div><strong>Assessment</strong>: {preview['assessment']} (<code>{preview['sharing_tag']}</code>)</div>
  <div><strong>Messages</strong>: {preview['messages']} • <strong>Feedback</strong>: 👍 {preview['feedback'].get('good',0)} • 👎 {preview['feedback'].get('bad',0)}</div>
  <div style='margin-top:8px'><strong>Tags</strong>:</div>
  <div>{', '.join(preview['tags']) or '<span class="muted">none</span>'}</div>
  <details style='margin-top:10px'><summary>Privacy Scan</summary><pre>{json.dumps(privacy, indent=2)}</pre></details>
</div>

<form class='card' method='post' action='/flywheel/submit'>
  <input type='hidden' name='chat_id' value='{chat_id}' />
  <div class='grid'>
    <div>
      <label>Attribution Mode</label>
      <select name='attribution_mode'>
        <option value='anonymous' {'selected' if attribution_mode=='anonymous' else ''}>Anonymous</option>
        <option value='pseudonym' {'selected' if attribution_mode=='pseudonym' else ''}>Pseudonym</option>
        <option value='huggingface' {'selected' if attribution_mode=='huggingface' else ''}>Hugging Face (requires token)</option>
      </select>
    </div>
    <div>
      <label>Hugging Face Write Token (not stored; used only to submit)</label>
      <input type='password' name='hf_user_token' placeholder='hf_xxx' />
      <div class='muted' style='margin-top:4px'>Docs: <a href='{HUGGINGFACE_TOKENS_DOC_URL}' target='_blank'>creating tokens</a></div>
    </div>
  </div>

  <div class='grid' style='margin-top:10px;'>
    <div>
      <label>Licensing Intent</label>
      <select name='license_intent'>
        <option {"selected" if license_intent=="AI devs who open‑source only" else ''}>AI devs who open‑source only</option>
        <option {"selected" if license_intent=="AI devs who contribute back to the ecosystem" else ''}>AI devs who contribute back to the ecosystem</option>
        <option {"selected" if license_intent=="Public bodies only" else ''}>Public bodies only</option>
        <option {"selected" if license_intent=="Research and nonprofit only" else ''}>Research and nonprofit only</option>
        <option {"selected" if license_intent=="Commercial use allowed with reciprocity" else ''}>Commercial use allowed with reciprocity</option>
        <option {"selected" if license_intent=="No AI training use" else ''}>No AI training use</option>
        <option {"selected" if license_intent=="Ask first / case‑by‑case" else ''}>Ask first / case‑by‑case</option>
      </select>
    </div>
    <div>
      <label>Licensing Note (optional)</label>
      <input type='text' name='license_intent_note' value='{license_intent_note}' />
    </div>
  </div>

  <div style='margin-top:10px;'>
    <label>Contributor Thoughts (optional)</label>
    <textarea name='ai_thoughts' rows='3'>{ai_thoughts}</textarea>
  </div>

  <div style='margin-top:12px;'>
    <button type='submit'>Submit Contribution</button>
  </div>
</form>
"""
        return page("Flywheel — Prepare", body)
    except Exception as e:
        return page("Flywheel — Error", f"<div class='card'><strong>Error:</strong> {type(e).__name__}: {e}</div>")


@app.post("/flywheel/submit")
def submit(
    chat_id: str = Form(...),
    attribution_mode: str = Form("anonymous"),
    hf_user_token: str = Form(""),
    license_intent: str = Form("AI devs who contribute back to the ecosystem"),
    license_intent_note: str = Form(""),
    ai_thoughts: str = Form(""),
):
    try:
        chat = get_full_chat(chat_id)
        clean = clean_messages(chat["messages"])
        messages_hash = hash_messages(clean)
        privacy = check_privacy(clean)
        sharing_tag, reason = compute_reason(chat["feedback_counts"])

        # Attribution string (simple replica of tool behavior)
        if attribution_mode == "pseudonym":
            attribution = "pseudonymous-contributor"
        elif attribution_mode == "huggingface":
            attribution = "Hugging Face account"
        else:
            attribution = "Anonymous"

        contribution = {
            "id": f"contrib_{secrets.token_urlsafe(8)}",
            "title": chat["title"],
            "clean_content": clean,
            "sharing_reason": reason,
            "sharing_tag": sharing_tag,
            "all_tags": sorted(set(chat["tags"])),
            "license_intent": license_intent,
            "license_intent_note": license_intent_note,
            "ai_thoughts": ai_thoughts,
            "attribution": attribution,
            "attribution_mode": attribution_mode,
            "verification": {"type": attribution_mode},
            "contributed_at": datetime.now(timezone.utc).isoformat(),
            "content_hash": messages_hash,
            "version": "1.0.0",
            "feedback_counts": chat["feedback_counts"],
            "response_labels": {},
        }

        # Real vs simulate
        if attribution_mode == "huggingface" and hf_user_token.strip():
            result = create_pr(contribution, hf_user_token.strip(), DEFAULT_DATASET_REPO)
            if result.get("success"):
                pr_number = result.get("pr_number")
                pr_url = result.get("pr_url")
                body = f"""
<div class='card'>
  <h3>Contribution sent! Thank you!</h3>
  <p><strong>Contribution #{pr_number}</strong>: <a href='{pr_url}' target='_blank'>View on Hugging Face</a></p>
  <div class='muted'>Hash: {messages_hash}</div>
</div>
"""
                return page("Flywheel — Sent", body)
            else:
                body = f"""
<div class='card'>
  <h3>Failed to create PR</h3>
  <div>{result.get('error')}</div>
</div>
"""
                return page("Flywheel — Error", body)
        else:
            # Simulated receipt
            mock_pr_number = 1234
            mock_pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(repo=DEFAULT_DATASET_REPO, num=mock_pr_number)
            body = f"""
<div class='card'>
  <h3>✅ Test Mode: PR Preview</h3>
  <ol>
    <li><strong>Pull Request</strong>: #{mock_pr_number}</li>
    <li><strong>Location</strong>: <a href='{mock_pr_url}' target='_blank'>{DEFAULT_DATASET_REPO}</a></li>
    <li><strong>Status</strong>: Awaiting review</li>
  </ol>
  <div class='muted'>Hash: {messages_hash}</div>
</div>
"""
            return page("Flywheel — Test Mode", body)

    except Exception as e:
        return page("Flywheel — Error", f"<div class='card'><strong>Error:</strong> {type(e).__name__}: {e}</div>")

