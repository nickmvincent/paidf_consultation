"""
title: Share to Flywheel
author: Nicholas Vincent
version: 0.5
required_open_webui_version: 0.5.0
description: Share conversations via Pull Requests for community moderation
icon_url: data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik00IDEydjdjMCAuNTUuNDUgMSAxIDFoMTRjLjU1IDAgMS0uNDUgMS0xdi03Ii8+PHBhdGggZD0iTTEyIDE2VjMiLz48cGF0aCBkPSJNOCA3bDQtNCA0IDQiLz48L3N2Zz4=
"""

import json
import re
import secrets
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict

from pydantic import BaseModel, Field


# ======================================================================
# URL Constants (edit here)
# ======================================================================
HUGGINGFACE_TOKENS_DOC_URL = "https://huggingface.co/docs/hub/en/security-tokens"
HUGGINGFACE_TOKENS_SETTINGS_URL = "https://huggingface.co/settings/tokens"
HUGGINGFACE_DATASET_DISCUSSION_URL = (
    "https://huggingface.co/datasets/{repo}/discussions/{num}"
)
DATALICENSES_URL = "https://datalicenses.org"
DEFAULT_FAQ_URL = "https://example.com/flywheel-faq"
DEFAULT_PRIVACY_POLICY_URL = "https://example.com/privacy"
PUBLICAI_GITHUB_URL = "https://github.com/publicai"


# ======================================================================
# TEMPLATES (edit here)
# ======================================================================

# Markers used to trim injected preview/setup text from the last message only.
# Keep these short and specific to top-level headings so we don't match
# normal conversation text.
TRIM_MARKERS: Tuple[str, str] = (
    "# Share Chat Publicly (Hugging Face)",
    "# Ready to Share:",
)

SETUP_TEMPLATE = """
# Share Chat Publicly (Hugging Face)

You can send specific chats to a public repository to share your good, bad, or interesting chats and help build better public AI. These chats can be used by anyone, subject to the experimental "AI preference signals" and the formal "licenses" you attach to the chats.

By default, your chats are not used directly for R&D. We may compute de‑identified aggregate stats (for example, total message volume) to operate the service.

You can always delete chats at any time or use temporary mode to ensure chats are not stored or used for any purpose.

How to setup public sharing:
1) Controls (top right) → Valves → Functions → Sharing
2) Toggle "Public Sharing Available" ON (Green)
3) Choose how you show up: Anonymous, Deterministic Pseudonym, or your Hugging Face account (requires a write token; learn more: {hf_tokens_doc_url})
4) Choose a Data Licensing Intent (declarative). Examples: "AI developers who open‑source only", "AI developers who contribute back to the ecosystem", "Public bodies only". We will translate these intents into enforceable options as the ecosystem stabilizes (see {datalicenses_url} and related efforts). For now, this captures your intent alongside the contribution.
5) Optional: Link your Hugging Face account to author PRs as you. Create a short‑lived write token at {hf_tokens_settings_url}, paste it, and we will verify it locally. Tokens are stored per‑user and never published.
6) Close Chat Controls once you're done, and then click the "Sharing" button under your chat again!

Data FAQ: {faq_url} • Privacy Policy: {privacy_policy_url}

"""

# Visible warning block (ALWAYS VISIBLE)
PUBLIC_DATA_WARNING = (
    "**⚠️ You are about to share a chat publicly.**"
)

# Summarized header shown above details
PREVIEW_HEADER = (
    "**Assessment**: **{reason}** (`{sharing_tag}`); **Messages**: {num_messages}; "
    "**Licensing Intent**: {license_intent}; **How you show up**: {attribution}; "
    "**Submitting via**: {submit_via}"
)

# Everything else placed in details
GRABBED_SECTION_TEMPLATE = """
<details>
<summary>Tags/feedbacks fetched for this chat</summary>

- **Tags**: {tags_line}
- **Feedback counts**: 👍 {good} • 👎 {bad} → **{reason_upper}**
- **Feedback samples** (up to 5):
~~~json
{sample_feedback_json}
~~~
</details>
"""

SHARE_JSON_BLOCK = """
<details>
<summary>Share Preview JSON (exactly what will be sent to HuggingFace)</summary>

~~~json
<<<SHARE_PREVIEW_START>>>
{json_str}
<<<SHARE_PREVIEW_END>>>
~~~
</details>
"""

PRIVACY_BLOCK = """
Privacy Scan (counts)
~~~json
{privacy_json}
~~~
"""


PREVIEW_TEMPLATE = """

# Ready to Share: "{title}"

{public_data_warning}

{tip_line}

Data FAQ: {faq_url} • Privacy Policy: {privacy_policy_url}

Privacy: {privacy_status}{privacy_note}

{intent_note_block}


<details>
<summary>Details</summary>

{preview_header}


{license_intent_block}
{ai_thoughts_block}

{privacy_block}

{grabbed_section}

</details>

{share_json_block}

**Next Step**: Click the Share button again to {next_verb} contribute.
"""

TEST_MODE_RESULT = """
# ✅ Test Mode: PR Preview

1) **Pull Request**: #{mock_pr_number}
2) **Location**: [{dataset_repo}]({mock_pr_url})
3) **Status**: Awaiting review

**Contribution**
- ID: `{contrib_id}`
- Assessment: {sharing_reason}
- Messages: {num_messages}
- Licensing Intent: {license_intent}
- Licensing Note: {license_intent_note}
- Contributor Thoughts (AI): {ai_thoughts}
 - Submitting via: {submit_via}
  - Contributor Display: {attribution}
"""

PR_CREATED_RESULT = """
# Contribution sent! Thank you!

**Contribution #{pr_number}**: [View on HuggingFace]({pr_url})

**Contribution Summary**
- Assessment: {sharing_reason}
- Messages: {num_messages}
- Licensing Intent: {license_intent}
- Licensing Note: {license_intent_note}
- Contributor Thoughts (AI): {ai_thoughts}
 - Submitting via: {submit_via}
  - Contributor Display: {attribution}
"""

PR_DESCRIPTION_TEMPLATE = """## Contribution Details

**Assessment**: {sharing_reason} (`{sharing_tag}`)
**Messages**: {num_messages}
**Attribution (declared)**: {attribution}

**Licensing Intent (declarative)**: {license_intent}
**Licensing Note**: {license_intent_note}
**Contributor Thoughts (AI)**:
{ai_thoughts}
**Content Hash**: `{content_hash}`
**Submitted**: {submitted_at}

**Attribution Mode**: {attribution_mode}
**Submitting via**: {submit_via}
**Verification**: {verification_json}
**Tags**: {tags_preview}

Submitted via the Flywheel OpenWebUI plugin.
"""

TIP_LINE = (
    "**Tip:** Update **tags** and **feedback** in the UI to add more detail to your contribution. "
    "We’ll auto‑grab the latest tags/feedback right before sending.\n"
)


PRIVACY_PATTERNS = {
    "phone_intl": (
        r"(?<!\d)\+(?:"
        r"(?:[1-9])(?:[-.\s]?\d){7,13}"
        r"|(?:[1-9]\d)(?:[-.\s]?\d){6,12}"
        r"|(?:[1-9]\d{2})(?:[-.\s]?\d){5,11}"
        r")(?!\d)"
    ),
    "phone_us": r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
    "phone_us_no_sep": r"(?<!\d)(?:\+?1)?(?:[2-9]\d{2}\d{7})(?!\d)",
    "email": (
        r"(?<![A-Za-z0-9._%+-])"
        r"[A-Za-z0-9](?:[A-Za-z0-9_%+\-]*[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9_%+\-]*[A-Za-z0-9])?)*"
        r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
        r"(?![A-Za-z0-9._%+-])"
    ),
    "ssn": r"(?<!\d)(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}(?!\d)",
    "ip_address": r"(?<!\d)(?<!\.)(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?!\.\d)(?!\d)",
    "ipv6_address": (
        r"(?<![A-Za-z0-9:])(" 
        r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:"
        r"|:(?::[A-Fa-f0-9]{1,4}){1,7}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}"
        r"|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}"
        r")(?!(?:[A-Za-z0-9:.]))"
    ),
    "aws_access_key": r"\b(?-i:(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16,17})\b",
    "aws_secret_key": r"\b[A-Za-z0-9/+=]{40}\b",
    "private_key": r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----",
    "api_key_stripe": r"\b(?:sk|pk)_(?:test_|live_)?[A-Za-z0-9]{24,}\b",
    "api_key_generic": r"\b(?:api[-_]?key|apikey|access[-_]?token)[-_:\s]*[A-Za-z0-9+/]{32,}\b",
    "street_address": r"\b\d{1,5}\s+(?:[NSEW]\.?\s+)?[A-Za-z0-9\s\-\.]{2,30}\s+(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr(?:ive)?|Ct|Court|Cir(?:cle)?|Pl(?:aza)?|Way|Pkwy|Parkway|Pike|Ter(?:race)?|Trail|Path|Loop|Run|Pass|Cross(?:ing)?|Sq(?:uare)?)\b",
    "credit_card": r"\b(?:\d[-\s]?){13,19}\b",
    "routing_number": r"\b(?:ABA|Routing)[-:\s]*\d{9}\b",
    "iban": (
        r"\b(?:AL|AD|AT|AZ|BH|BE|BA|BR|BG|CR|HR|CY|CZ|DK|DO|EE|FO|FI|FR|GE|DE|GI|GR|GL|GT|HU|IS|IE|IL|IT|JO|KZ|KW|LV|LB|LI|LT|LU|MT|MR|MU|MC|MD|ME|NL|NO|PK|PS|PL|PT|QA|RO|SM|SA|RS|SK|SI|ES|SE|CH|TN|TR|AE|GB|VG|XK)\d{2}[A-Z0-9]{4,30}\b"
    ),
    "us_passport": r"\b(?:[0-9]{9}|[A-Z][0-9]{8})\b",
    "ein": r"\b\d{2}-\d{7}\b",
    "medicare": r"\b[A-Z0-9]{4}-[A-Z0-9]{3}-[A-Z0-9]{4}\b",
    "bitcoin_address": r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b",
    "ethereum_address": r"\b0x[a-fA-F0-9]{40}\b",
}

# ======================================================================
# Types
# ======================================================================

class Contribution(TypedDict, total=True):
    id: str
    title: str
    clean_content: List[Dict[str, Any]]
    sharing_reason: Literal["good", "bad", "mixed"]
    sharing_tag: Literal["dataset-good", "dataset-bad", "dataset-mixed"]
    all_tags: List[str]
    license_intent: str
    license_intent_note: str
    ai_thoughts: str
    attribution: str
    attribution_mode: Literal["anonymous", "pseudonym", "huggingface"]
    verification: Dict[str, Any]
    contributed_at: str
    content_hash: str
    version: str
    feedback_counts: Dict[str, int]
    # Map of clean_content message index (stringified) -> "good" | "bad"
    # note: this could be explained better / possibly refactored
    response_labels: Dict[str, Literal["good", "bad"]]


def validate_contribution(c: Dict[str, Any]) -> Contribution:
    required_keys = {
        "id",
        "title",
        "clean_content",
        "sharing_reason",
        "sharing_tag",
        "all_tags",
        "license_intent",
        "license_intent_note",
        "ai_thoughts",
        "attribution",
        "attribution_mode",
        "verification",
        "contributed_at",
        "content_hash",
        "version",
        "feedback_counts",
        "response_labels",
    }
    missing = required_keys - set(c.keys())
    if missing:
        raise ValueError(f"Missing contribution keys: {sorted(missing)}")

    if c["sharing_reason"] not in ("good", "bad", "mixed"):
        raise ValueError("sharing_reason must be 'good' | 'bad' | 'mixed'")
    if c["sharing_tag"] not in ("dataset-good", "dataset-bad", "dataset-mixed"):
        raise ValueError(
            "sharing_tag must be 'dataset-good' | 'dataset-bad' | 'dataset-mixed'"
        )
    if c["attribution_mode"] not in ("anonymous", "pseudonym", "huggingface"):
        raise ValueError("attribution_mode invalid")
    if not isinstance(c["license_intent"], str) or not c["license_intent"].strip():
        raise ValueError("license_intent must be a non-empty string")
    if not isinstance(c.get("license_intent_note"), str):
        raise ValueError("license_intent_note must be a string")
    if not isinstance(c.get("ai_thoughts"), str):
        raise ValueError("ai_thoughts must be a string")
    if not isinstance(c["clean_content"], list) or not c["clean_content"]:
        raise ValueError("clean_content must be a non-empty list")
    if not isinstance(c["feedback_counts"], dict):
        raise ValueError("feedback_counts must be a dict")
    if not isinstance(c.get("response_labels"), dict):
        raise ValueError("response_labels must be a dict mapping indexes to labels")
    return c  # type: ignore[return-value]

# ======================================================================
# Config
# ======================================================================

class Action:
    class Valves(BaseModel):
        default_hf_token: str = Field(
            default="", description="Service HF token used by the app to open PRs"
        )
        dataset_repo: str = Field(
            default="publicai/shared-chats", description="Dataset repo (owner/name)"
        )
        sanity_check_repo: bool = Field(
            default=True, description="Preflight: verify repo exists and token perms"
        )
        faq_url: str = Field(
            default=DEFAULT_FAQ_URL, description="Data FAQ"
        )
        privacy_policy_url: str = Field(
            default=DEFAULT_PRIVACY_POLICY_URL, description="Privacy Policy"
        )
        min_messages: int = Field(
            default=2, description="Minimum messages required to share"
        )
        max_messages: int = Field(
            default=100, description="Maximum messages allowed per share (lowered)"
        )
        

    class UserValves(BaseModel):
        public_sharing_available: bool = Field(
            default=False, description="Enable public sharing workflow"
        )

        attribution_mode: Literal["anonymous", "pseudonym", "huggingface"] = Field(
            default="anonymous",
            description=(
                "How your name appears: "
                "anonymous = least linkability; "
                "pseudonym = deterministic handle from your account id; "
                "huggingface = submit PRs using your Hugging Face account (requires write token)."
            ),
        )

        license_intent: Literal[
            "AI devs who open‑source only",
            "AI devs who contribute back to the ecosystem",
            "Public bodies only",
            "Research and nonprofit only",
            "Commercial use allowed with reciprocity",
            "No AI training use",
            "Ask first / case‑by‑case",
        ] = Field(
            default="AI devs who contribute back to the ecosystem",
            description=(
                "High‑level intent for data use. We will translate this into enforceable "
                "terms as standards mature (see datalicenses.org)."
            ),
        )
        license_intent_note: str = Field(
            default="",
            description=(
                "Optional note to clarify your licensing intent (e.g., what counts as reciprocity, acceptable open‑source licenses, or public body scope)."
            ),
        )
        ai_thoughts: str = Field(
            default="",
            description=(
                "Optional: Your open‑ended thoughts about AI to include with the contribution."
            ),
        )

        hf_user_token: str = Field(
            default="",
            description=(
                f"Your Hugging Face write token; (Never published; this action is open source so you can see exactly what we're doing with the token!). "
                f"Create/manage at {HUGGINGFACE_TOKENS_DOC_URL}"
            ),
        )

    def __init__(self):
        self.valves = self.Valves()
        self.user_valves = self.UserValves()
        self.db_path = str(Path.home() / ".open-webui" / "webui.db")
        self.recent_submissions: Dict[str, Tuple[datetime, str]] = (
            {}
        )  # chat_id -> (timestamp, pr_number)

    def _public_data_warning(self, user_valves: "Action.UserValves") -> str:
        return PUBLIC_DATA_WARNING

# ------------------------------------------------------------------
# Dedup guard
# ------------------------------------------------------------------
    # Minimum gap to consider two submissions duplicates (in minutes)
    DUP_WINDOW_MINUTES = 5

    def _check_duplicate_submission(self, chat_id: str) -> Tuple[bool, str]:
        if chat_id in self.recent_submissions:
            last_submit_time, pr_number = self.recent_submissions[chat_id]
            time_diff = datetime.now(timezone.utc) - last_submit_time
            if time_diff < timedelta(minutes=self.DUP_WINDOW_MINUTES):
                seconds_ago = int(time_diff.total_seconds())
                pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(
                    repo=self.valves.dataset_repo, num=pr_number
                )
                return (
                    True,
                    f"This chat was shared {seconds_ago} seconds ago. [View PR #{pr_number}]({pr_url})",
                )
        return False, ""

    def _record_submission(self, chat_id: str, pr_number: int):
        self.recent_submissions[chat_id] = (datetime.now(timezone.utc), pr_number)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        self.recent_submissions = {
            cid: (ts, pr)
            for cid, (ts, pr) in self.recent_submissions.items()
            if ts > cutoff
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _norm_tags(self, tags: List[str]) -> List[str]:
        return sorted(
            {
                (t or "").strip().lower()
                for t in tags
                if isinstance(t, str) and t.strip()
            }
        )

    def _hash_messages(self, messages: List[Dict[str, Any]]) -> str:
        # include model and tool_calls for better reproducibility
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

    def _sanitize_contribution_for_export(
        self, contribution: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Return a copy safe for sharing externally.
        - Remove internal/sensitive fields
        - Add a brief note about content_hash purpose
        """
        out = dict(contribution)
        # Remove fields we do not want to publish
        out.pop("source_chat_id", None)
        # Add note about content_hash for transparency
        if out.get("content_hash") and not out.get("content_hash_note"):
            out["content_hash_note"] = (
                "Shared to help detect duplicates and verify integrity without exposing raw text."
            )
        return out

    # Deterministic pseudonym from user id only
    def _deterministic_pseudonym(self, user_obj: Dict[str, Any]) -> str:
        uid = (
            (user_obj or {}).get("id")
            or (user_obj or {}).get("username")
            or (user_obj or {}).get("profile", {}).get("username")
            or "anon"
        )
        h = hashlib.sha256(str(uid).encode()).hexdigest()
        adjectives = [
            "swift",
            "calm",
            "bright",
            "clever",
            "brave",
            "curious",
            "quiet",
            "lucky",
            "merry",
            "stellar",
        ]
        nouns = [
            "otter",
            "lynx",
            "falcon",
            "willow",
            "ember",
            "quartz",
            "spruce",
            "aurora",
            "delta",
            "river",
        ]
        a = adjectives[int(h[:2], 16) % len(adjectives)]
        n = nouns[int(h[2:4], 16) % len(nouns)]
        num = int(h[4:8], 16) % 1000
        return f"{a}-{n}-{num:03d}"

    # Privacy scan (improved, counts only)
    def _luhn_ok(self, s: str) -> bool:
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

    def _check_privacy(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    
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
                    good = [m for m in matches if self._luhn_ok(m)]
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


    

    # DB helpers
    def _get_full_chat_data(self, chat_id: str) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM chat WHERE id = ?", (chat_id,))
        chat_row = cur.fetchone()
        if not chat_row:
            conn.close()
            raise ValueError("Chat not found")
        chat_row = dict(chat_row)

        # tags from chatidtag table + any tags in chat.meta/chat payload
        cur.execute("SELECT tag_name FROM chatidtag WHERE chat_id = ?", (chat_id,))
        tags_rows = [r["tag_name"] for r in cur.fetchall() if r and r["tag_name"]]

        # meta (unused for tags, but kept)
        try:
            raw_meta = chat_row.get("meta")
            meta_json = (
                json.loads(raw_meta) if isinstance(raw_meta, str) else (raw_meta or {})
            )
        except Exception:
            meta_json = {}
        # Merge-in tags if present in meta
        meta_tags = []
        try:
            maybe_tags = (meta_json or {}).get("tags")
            if isinstance(maybe_tags, list):
                meta_tags = [t for t in maybe_tags if isinstance(t, str)]
        except Exception:
            meta_tags = []

        # messages
        try:
            raw_chat = chat_row.get("chat")
            chat_json = (
                json.loads(raw_chat) if isinstance(raw_chat, str) else (raw_chat or {})
            )
        except Exception:
            chat_json = {}
        messages = chat_json.get("messages", []) if isinstance(chat_json, dict) else []
        # Merge-in tags if present in chat payload
        chat_tags = []
        try:
            maybe_ctags = (chat_json or {}).get("tags") if isinstance(chat_json, dict) else []
            if isinstance(maybe_ctags, list):
                chat_tags = [t for t in maybe_ctags if isinstance(t, str)]
        except Exception:
            chat_tags = []

        # Combine tag sources
        tags = [*tags_rows, *meta_tags, *chat_tags]

        # feedback (support multiple locations/keys for chat id)
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
        feedback_items: List[Dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            for k in ("data", "meta"):
                if isinstance(d.get(k), str):
                    try:
                        d[k] = json.loads(d[k])
                    except Exception:
                        pass
            feedback_items.append(d)

        def _num_or_none(x):
            try:
                return int(x)
            except Exception:
                try:
                    return float(x)
                except Exception:
                    return None

        def is_good(item):
            t = (item.get("type") or "").lower()
            if t in ("good", "good_response", "thumbs_up"):
                return True
            data = item.get("data") or {}
            rnum = _num_or_none(data.get("rating"))
            if rnum is not None:
                return rnum > 0
            r = str(data.get("rating", "")).lower()
            return r in ("good", "thumbs_up", "up", "1", "+1", "positive")

        def is_bad(item):
            t = (item.get("type") or "").lower()
            if t in ("bad", "bad_response", "thumbs_down"):
                return True
            data = item.get("data") or {}
            rnum = _num_or_none(data.get("rating"))
            if rnum is not None:
                return rnum < 0
            r = str(data.get("rating", "")).lower()
            return r in ("bad", "thumbs_down", "down", "-1", "negative")

        good = sum(1 for it in feedback_items if is_good(it))
        bad = sum(1 for it in feedback_items if is_bad(it))

        conn.close()
        return {
            "chat_id": chat_id,
            "title": chat_row.get("title", "Untitled Chat"),
            "created_at": chat_row.get("created_at"),
            "updated_at": chat_row.get("updated_at"),
            "messages": messages,
            "tags": tags,
            "meta": meta_json,
            "feedback_items": feedback_items,
            "feedback_counts": {"good": good, "bad": bad},
        }

    def _compute_sharing_reason(
        self, feedback_counts: Dict[str, int]
    ) -> Tuple[str, str]:
        good, bad = feedback_counts.get("good", 0), feedback_counts.get("bad", 0)
        if good > bad:
            return "dataset-good", "good"
        if bad > good:
            return "dataset-bad", "bad"
        return "dataset-mixed", "mixed"

    def _resolve_attribution(
        self, user_valves: "Action.UserValves", user_obj: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        mode = user_valves.attribution_mode
        if mode == "anonymous":
            return "Anonymous", {"type": "none", "status": "unverified"}
        if mode == "pseudonym":
            name = self._deterministic_pseudonym(user_obj)
            return name, {"type": "pseudonym", "status": "deterministic"}
        if mode == "huggingface":
            return "Hugging Face account", {"type": "hf", "status": "token_required"}
        return "Anonymous", {"type": "none", "status": "unverified"}

    # HF preflight & PR
    def _hf_preflight(self, hf_token: str) -> dict:
        out = {"ok": True, "errors": [], "who": None, "repo": None}
        try:
            from huggingface_hub import HfApi  # type: ignore

            api = HfApi()
            try:
                out["who"] = api.whoami(token=hf_token)
            except Exception as e:
                out["ok"] = False
                out["errors"].append(f"whoami failed: {e}")
            try:
                repo = api.repo_info(
                    repo_id=self.valves.dataset_repo,
                    repo_type="dataset",
                    token=hf_token,
                )
                out["repo"] = {
                    "name": getattr(repo, "name", None),
                    "owner": getattr(repo, "owner", None),
                    "private": getattr(repo, "private", None),
                }
            except Exception as e:
                out["ok"] = False
                out["errors"].append(f"repo_info failed: {e}")
        except Exception as e:
            out["ok"] = False
            out["errors"].append(f"preflight critical: {e}")
        return out

    def _create_pull_request(
        self, contribution: Contribution, hf_token: str, dataset_repo: str
    ) -> Dict[str, Any]:
        try:
            from huggingface_hub import HfApi, CommitOperationAdd  # type: ignore
            import io

            api = HfApi()
            file_path = f"contributions/{contribution['id']}.json"
            safe_contribution = self._sanitize_contribution_for_export(contribution)
            json_content = json.dumps(safe_contribution, indent=2, ensure_ascii=False)

            pr_title = "[{sharing_reason}] Contribution ({attribution})".format(
                sharing_reason=contribution["sharing_reason"],
                attribution=contribution.get("attribution", "anonymous"),
            )
            pr_description = PR_DESCRIPTION_TEMPLATE.format(
                sharing_reason=contribution["sharing_reason"],
                sharing_tag=contribution["sharing_tag"],
                num_messages=len(contribution["clean_content"]),
                attribution=contribution.get("attribution", "anonymous"),
                license_intent=contribution.get("license_intent", "unspecified"),
                license_intent_note=contribution.get("license_intent_note", "—") or "—",
                ai_thoughts=contribution.get("ai_thoughts", "—") or "—",
                content_hash=contribution.get("content_hash", "N/A"),
                submitted_at=contribution["contributed_at"],
                attribution_mode=contribution.get("attribution_mode", "anonymous"),
                submit_via=contribution.get("submit_via", "app account"),
                verification_json=json.dumps(
                    contribution.get("verification", {}), ensure_ascii=False
                ),
                tags_preview=", ".join(
                    "`{}`".format(t) for t in contribution["all_tags"][:10]
                ),
            )

            commit_info = api.create_commit(
                repo_id=dataset_repo,
                operations=[
                    CommitOperationAdd(
                        path_in_repo=file_path,
                        path_or_fileobj=io.BytesIO(json_content.encode()),
                    )
                ],
                commit_message=pr_title,
                commit_description=pr_description,
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
            return {"success": False, "error": "{}: {}".format(type(e).__name__, e)}

    def _clean_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simplify messages; trim preview markers from the last message.
        Preserves `id`, `model`, and `tool_calls` if present.
        """
        clean: List[Dict[str, Any]] = []

        def _trim_last_message_content(content: str) -> str:
            if not isinstance(content, str):
                return content
            cut = None
            for m in TRIM_MARKERS:
                idx = content.find(m)
                if idx != -1:
                    cut = idx if cut is None else min(cut, idx)
            if cut is not None:
                return content[:cut].rstrip()
            return content

        last_idx = len(messages) - 1
        for i, msg in enumerate(messages):
            if not (isinstance(msg, dict) and "role" in msg and "content" in msg):
                continue
            content = msg.get("content")
            if i == last_idx and isinstance(content, str):
                content = _trim_last_message_content(content)
                if not content:
                    continue
            cm = {"role": msg["role"], "content": content}
            if "id" in msg:
                cm["id"] = msg["id"]
            if "model" in msg:
                cm["model"] = msg["model"]
            if "tool_calls" in msg:
                cm["tool_calls"] = msg["tool_calls"]
            clean.append(cm)
        return clean

    def _detect_workflow_stage(
        self, messages: List[Dict[str, Any]]
    ) -> Tuple[str, Optional[str]]:
        """Detect first_run vs confirm_run by scanning for preview sentinels."""
        WORKFLOW_SCAN_DEPTH = 25
        if not messages:
            return "first_run", None
        for msg in reversed(messages[-WORKFLOW_SCAN_DEPTH:]):
            content = msg.get("content", "") or ""
            if (
                "<<<SHARE_PREVIEW_START>>>" in content
                and "<<<SHARE_PREVIEW_END>>>" in content
            ):
                if "**Next Step**: Click the Share button again" in content:
                    return "confirm_run", content
                else:
                    return "first_run", None
        return "first_run", None

    def _extract_json_from_preview(self, content: str) -> Optional[Dict[str, Any]]:
        """Extract JSON payload between preview sentinels (or None)."""
        m = re.search(
            r"<<<SHARE_PREVIEW_START>>>\s*(.*?)\s*<<<SHARE_PREVIEW_END>>>",
            content,
            re.DOTALL,
        )
        if m:
            try:
                return json.loads(m.group(1).strip())
            except json.JSONDecodeError:
                return None
        return None

    def _map_response_labels(
        self,
        raw_messages: List[Dict[str, Any]],
        clean_messages: List[Dict[str, Any]],
        feedback_items: List[Dict[str, Any]],
    ) -> Dict[str, Literal["good", "bad"]]:
        """Simplified mapping for OpenWebUI shapes:
        - Feedback type is usually "rating" with numeric data.rating 1/-1
        - meta.message_id refers to the target message id
        - meta.message_index is a raw message index fallback
        """
        # Build raw->clean index map and id->clean
        raw_to_clean: Dict[int, int] = {}
        ci = 0
        for ri, msg in enumerate(raw_messages):
            if isinstance(msg, dict) and "role" in msg and "content" in msg:
                raw_to_clean[ri] = ci
                ci += 1

        id_to_clean: Dict[str, int] = {}
        for idx, msg in enumerate(clean_messages):
            mid = msg.get("id")
            if isinstance(mid, str):
                id_to_clean[mid] = idx

        def label_from_rating(val) -> Optional[Literal["good", "bad"]]:
            try:
                if val is None:
                    return None
                n = int(val)
                if n > 0:
                    return "good"
                if n < 0:
                    return "bad"
                return None
            except Exception:
                return None

        labels: Dict[str, Literal["good", "bad"]] = {}
        for it in feedback_items:
            data = it.get("data") or {}
            meta = it.get("meta") or {}
            label = label_from_rating((data or {}).get("rating"))
            if not label:
                continue

            # Prefer message_id match
            mid = meta.get("message_id") or data.get("message_id")
            if isinstance(mid, str) and mid in id_to_clean:
                key = str(id_to_clean[mid])
                if key not in labels:
                    labels[key] = label
                continue

            # Fallback: raw message index
            idx_raw = meta.get("message_index")
            try:
                if idx_raw is not None:
                    idx_raw_int = int(idx_raw)
                    if idx_raw_int in raw_to_clean:
                        key = str(raw_to_clean[idx_raw_int])
                        if key not in labels:
                            labels[key] = label
                        continue
            except Exception:
                pass

        return labels

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------
    async def action(
        self, body: dict, __user__=None, __event_emitter__=None, __event_call__=None
    ):
        user_valves = (__user__ or {}).get("valves")
        chat_id = (body or {}).get("chat_id")
        messages = (body or {}).get("messages", [])

        if not chat_id:
            await __event_emitter__(
                {
                    "type": "notification",
                    "data": {"type": "error", "content": "No chat selected"},
                }
            )
            return

        # Entry / setup screen
        if not user_valves or not user_valves.public_sharing_available:
            await __event_emitter__(
                {
                    "type": "message",
                    "data": {
                        "content": SETUP_TEMPLATE.format(
                            faq_url=self.valves.faq_url,
                            privacy_policy_url=self.valves.privacy_policy_url,
                            hf_tokens_doc_url=HUGGINGFACE_TOKENS_DOC_URL,
                            hf_tokens_settings_url=HUGGINGFACE_TOKENS_SETTINGS_URL,
                            datalicenses_url=DATALICENSES_URL,
                        )
                    },
                }
            )
            return

        try:
            stage, preview_content = self._detect_workflow_stage(messages)

            # FIRST RUN → Build preview
            if stage == "first_run":
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Analyzing conversation...",
                            "done": False,
                        },
                    }
                )

                chat = self._get_full_chat_data(chat_id)
                clean_messages = self._clean_messages(chat["messages"])

                # length checks
                if len(clean_messages) < self.valves.min_messages:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "warning",
                                "content": "Too short. Minimum {} messages required.".format(
                                    self.valves.min_messages
                                ),
                            },
                        }
                    )
                    return
                if len(clean_messages) > self.valves.max_messages:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "warning",
                                "content": "Too long. Maximum {} messages. Consider splitting.".format(
                                    self.valves.max_messages
                                ),
                            },
                        }
                    )
                    return

                # dedup short-circuit
                is_dup, dup_msg = self._check_duplicate_submission(chat_id)
                if is_dup:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {"type": "warning", "content": dup_msg},
                        }
                    )
                    return

                # PII scan (counts only)
                privacy = self._check_privacy(clean_messages)
                privacy_status = (
                    "✅ No obvious personal data detected"
                    if not privacy["has_issues"]
                    else "⚠️ Potential personal data detected (expand 'Details')"
                )
                privacy_note = ""
                if privacy["has_issues"]:
                    types_str = ", ".join(privacy["types_found"][:3])
                    privacy_note = "\n\n**Privacy Warning**: Possible {}. Review before sharing.".format(
                        types_str
                    )


                # attribution
                attribution, verification = self._resolve_attribution(
                    user_valves, __user__
                )

                # compute reason from saved feedbacks
                sharing_tag, reason = self._compute_sharing_reason(
                    chat["feedback_counts"]
                )

                # normalized tags for display
                norm_tags = self._norm_tags(chat["tags"])

                # transparency: feedback samples
                def _safe_get(d, *keys, default=None):
                    cur = d
                    for k in keys:
                        if not isinstance(cur, dict):
                            return default
                        cur = cur.get(k)
                    return cur if cur is not None else default

                sample_feedback = []
                for it in chat["feedback_items"][:5]:
                    data = it.get("data") or {}
                    meta = it.get("meta") or {}
                    sample_feedback.append(
                        {
                            "id": it.get("id"),
                            "type": it.get("type"),
                            "rating": data.get("rating"),
                            "model_id": _safe_get(data, "model_id")
                            or _safe_get(meta, "model_id"),
                            "chat_id": _safe_get(meta, "chat_id"),
                            "created_at": it.get("created_at"),
                            "tags": (
                                data.get("tags")
                                if isinstance(data.get("tags"), list)
                                else None
                            ),
                        }
                    )
                sample_feedback_json = json.dumps(
                    sample_feedback, indent=2, ensure_ascii=False
                )

                # build contribution
                contrib_id = "contrib_{}".format(secrets.token_urlsafe(8))
                messages_hash = self._hash_messages(clean_messages)
                response_labels = self._map_response_labels(chat["messages"], clean_messages, chat["feedback_items"])  # map feedback to specific responses

                contribution: Contribution = validate_contribution(
                    {
                        "id": contrib_id,
                        "title": chat["title"],
                        "clean_content": clean_messages,
                        "sharing_reason": reason,
                        "sharing_tag": sharing_tag,
                        "all_tags": norm_tags,
                        "license_intent": user_valves.license_intent,
                        "license_intent_note": user_valves.license_intent_note,
                        "ai_thoughts": user_valves.ai_thoughts,
                        "attribution": attribution,
                        "attribution_mode": user_valves.attribution_mode,
                        "verification": verification,
                        "contributed_at": datetime.now(timezone.utc).isoformat(),
                        "content_hash": messages_hash,
                        "version": "1.0.0",
                        "feedback_counts": chat["feedback_counts"],
                        "response_labels": response_labels,
                        }
                )

                # Show exactly what will be sent (sanitized for export)
                export_contribution = self._sanitize_contribution_for_export(contribution)
                json_str = json.dumps(export_contribution, indent=2, ensure_ascii=False)

                # Determine submission route for preview
                use_user_token = (
                    user_valves.attribution_mode == "huggingface" and (user_valves.hf_user_token or "").strip()
                )
                have_app_token = bool(self.valves.default_hf_token and self.valves.dataset_repo)
                submit_via = (
                    "your Hugging Face account" if use_user_token else (
                        "app account" if have_app_token else "simulation"
                    )
                )
                next_verb = ("create" if (use_user_token or have_app_token) else "simulate")

                # Blocks
                grabbed_section = GRABBED_SECTION_TEMPLATE.format(
                    tags_line=(
                        ", ".join("`{}`".format(t) for t in norm_tags)
                        if norm_tags
                        else "_none_"
                    ),
                    good=chat["feedback_counts"].get("good", 0),
                    bad=chat["feedback_counts"].get("bad", 0),
                    reason_upper=reason.upper(),
                    sample_feedback_json=sample_feedback_json,
                )

                share_json_block = SHARE_JSON_BLOCK.format(json_str=json_str)
                privacy_block = PRIVACY_BLOCK.format(
                    privacy_json=json.dumps(privacy, indent=2)
                )

                # Human-readable definition appended to selected preference
                preview_md = PREVIEW_TEMPLATE.format(
                    title=chat["title"],
                    public_data_warning=self._public_data_warning(user_valves),
                    preview_header=PREVIEW_HEADER.format(
                        reason=reason,
                        sharing_tag=sharing_tag,
                        num_messages=len(clean_messages),
                        license_intent=(user_valves.license_intent or "unspecified"),
                        attribution=attribution,
                        submit_via=submit_via,
                    ),
                    privacy_status=privacy_status,
                    privacy_note=privacy_note,
                    grabbed_section=grabbed_section,
                    tip_line=TIP_LINE,
                    faq_url=self.valves.faq_url,
                    privacy_policy_url=self.valves.privacy_policy_url,
                    share_json_block=share_json_block,
                    privacy_block=privacy_block,
                    license_intent_block=(
                        "- Data Licensing Intent: {}\n- Note: {}\n\n_We will translate these intents into concrete licensing actions as standards mature (e.g., {})._.".format(
                            user_valves.license_intent or "unspecified",
                            (user_valves.license_intent_note or "—"),
                            DATALICENSES_URL,
                        )
                    ),
                    ai_thoughts_block=(
                        "- Contributor Thoughts (AI): {}\n".format(user_valves.ai_thoughts.strip()) if (user_valves.ai_thoughts or "").strip() else ""
                    ),
                    intent_note_block=(
                        """
                        Note on Licensing Intents and AI Thoughts
                        
                        We capture your natural‑language licensing intent and any optional thoughts on AI. As standards mature, we will translate these into concrete licenses and/or AI‑use preference signals. For now, there is no firm legal contract: submissions are published publicly on Hugging Face with a lightweight contributor agreement and may be mirrored later on a static site with anti‑scraping. As the Public AI movement grows, we’ll formalize this. Iterating on licenses and signals is a great way to contribute — join us on GitHub: {publicai_github_url}
                        """.strip().format(publicai_github_url=PUBLICAI_GITHUB_URL)
                    ),
                    next_verb=next_verb,
                )

                await __event_emitter__(
                    {"type": "message", "data": {"content": preview_md}}
                )
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {"description": "Complete", "done": True},
                    }
                )
                return

            # CONFIRM RUN → re-compare and (mock|real) PR
            else:
                contribution = self._extract_json_from_preview(preview_content)
                if not contribution:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "error",
                                "content": "Could not read preview data. Try again.",
                            },
                        }
                    )
                    return

                try:
                    contribution = validate_contribution(contribution)  # type: ignore[assignment]
                except Exception as e:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "error",
                                "content": "Preview invalid: {}".format(e),
                            },
                        }
                    )
                    return

                # fresh state
                chat = self._get_full_chat_data((body or {}).get("chat_id"))
                fresh_messages = self._clean_messages(
                    chat["messages"]
                )  # kept for PR payload and hash record
                fresh_hash = self._hash_messages(fresh_messages)

                # recompute reason from fresh feedback
                new_sharing_tag, new_reason = self._compute_sharing_reason(
                    chat["feedback_counts"]
                )

                # normalized comparisons
                preview_tags = self._norm_tags(contribution.get("all_tags", []))
                fresh_tags = self._norm_tags(chat["tags"])
                preview_feedback = {
                    "good": int(contribution.get("feedback_counts", {}).get("good", 0)),
                    "bad": int(contribution.get("feedback_counts", {}).get("bad", 0)),
                }
                fresh_feedback = {
                    "good": int(chat["feedback_counts"].get("good", 0)),
                    "bad": int(chat["feedback_counts"].get("bad", 0)),
                }

                # Always refresh tags/feedback just-in-time, and proceed
                changed = (preview_tags != fresh_tags) or (preview_feedback != fresh_feedback)

                attribution, verification = self._resolve_attribution(user_valves, __user__)
                contribution.update(
                    {
                        "clean_content": fresh_messages,
                        "content_hash": fresh_hash,
                        "all_tags": fresh_tags,
                        "feedback_counts": fresh_feedback,
                        "response_labels": self._map_response_labels(chat["messages"], fresh_messages, chat["feedback_items"]),
                        "sharing_tag": new_sharing_tag,
                        "sharing_reason": new_reason,
                        "attribution": attribution,
                        "verification": verification,
                        "license_intent": user_valves.license_intent,
                        "license_intent_note": user_valves.license_intent_note,
                        "ai_thoughts": user_valves.ai_thoughts,
                        "contributed_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                try:
                    contribution = validate_contribution(contribution)  # type: ignore[assignment]
                except Exception as e:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "error",
                                "content": "Updated data invalid: {}".format(e),
                            },
                        }
                    )
                    return

                if changed:
                    # Toast: confirm latest tags/feedback were grabbed
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "success",
                                "content": "Latest tags/feedback grabbed: tags={} • 👍 {} • 👎 {}".format(
                                    len(fresh_tags), fresh_feedback.get("good", 0), fresh_feedback.get("bad", 0)
                                ),
                            },
                        }
                    )

                # proceed to PR (mock if creds missing or manual_hf)
                # Choose token: prefer user-linked when attribution_mode is huggingface
                use_user_token = (
                    user_valves.attribution_mode == "huggingface" and (user_valves.hf_user_token or "").strip()
                )
                hf_token = user_valves.hf_user_token if use_user_token else self.valves.default_hf_token
                have_hf_creds = bool(hf_token and self.valves.dataset_repo)
                # Manual mode only when user requested huggingface but token missing
                manual_mode = (user_valves.attribution_mode == "huggingface" and not use_user_token)

                if have_hf_creds and not manual_mode and self.valves.sanity_check_repo:
                    pf = self._hf_preflight(hf_token)
                    if not pf.get("ok"):
                        lines = ["Preflight checks failed:"]
                        lines += ["- {}".format(e) for e in pf.get("errors", [])]
                        who = pf.get("who") or {}
                        if who:
                            lines.append(
                                "- Token user: {}".format(
                                    who.get("name")
                                    or who.get("email")
                                    or who.get("orgs", [])
                                )
                            )
                        await __event_emitter__(
                            {
                                "type": "notification",
                                "data": {"type": "error", "content": "\n".join(lines)},
                            }
                        )
                        return

                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {"description": "Submitting...", "done": False},
                    }
                )

                if (not have_hf_creds) or manual_mode:
                    mock_pr_number = "MOCK-123"
                    mock_pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(
                        repo=self.valves.dataset_repo, num=mock_pr_number
                    )
                    result = TEST_MODE_RESULT.format(
                        mock_pr_number=mock_pr_number,
                        dataset_repo=self.valves.dataset_repo,
                        mock_pr_url=mock_pr_url,
                        contrib_id=contribution["id"],
                        sharing_reason=contribution["sharing_reason"],
                        num_messages=len(contribution["clean_content"]),
                        license_intent=contribution.get("license_intent", "unspecified"),
                        license_intent_note=contribution.get("license_intent_note", "—") or "—",
                        ai_thoughts=contribution.get("ai_thoughts", "—") or "—",
                        submit_via=("your Hugging Face account" if use_user_token else ("app account" if self.valves.default_hf_token else "simulation")),
                        attribution=contribution.get("attribution", "anonymous"),
                    )
                else:
                    try:
                        from huggingface_hub import HfApi  # noqa: F401
                    except ImportError:
                        await __event_emitter__(
                            {
                                "type": "notification",
                                "data": {
                                    "type": "error",
                                    "content": "huggingface_hub not installed. Admin: `pip install huggingface_hub`",
                                },
                            }
                        )
                        return

                    # include submit_via in contribution for PR description
                    export_contribution = self._sanitize_contribution_for_export({
                        **contribution,
                        "submit_via": ("your Hugging Face account" if use_user_token else "app account"),
                    })
                    pr_result = self._create_pull_request(
                        export_contribution,
                        hf_token,
                        self.valves.dataset_repo,
                    )
                    if pr_result["success"]:
                        if pr_result.get("pr_number"):
                            self._record_submission(chat_id, pr_result["pr_number"])
                        pr_url = pr_result["pr_url"]
                        pr_number = pr_result.get("pr_number", "N/A")
                        result = PR_CREATED_RESULT.format(
                            pr_number=pr_number,
                            pr_url=pr_url,
                            contrib_id=contribution["id"],
                            sharing_reason=contribution["sharing_reason"],
                            num_messages=len(contribution["clean_content"]),
                            license_intent=contribution.get("license_intent", "unspecified"),
                            license_intent_note=contribution.get("license_intent_note", "—") or "—",
                            ai_thoughts=contribution.get("ai_thoughts", "—") or "—",
                            submit_via=("your Hugging Face account" if use_user_token else "app account"),
                            attribution=contribution.get("attribution", "anonymous"),
                        )
                    else:
                        detail = pr_result.get("error", "Unknown error")
                        await __event_emitter__(
                            {
                                "type": "notification",
                                "data": {
                                    "type": "error",
                                    "content": "PR creation failed: {}".format(detail),
                                },
                            }
                        )
                        return

                await __event_emitter__(
                    {"type": "message", "data": {"content": result}}
                )
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {"description": "Complete", "done": True},
                    }
                )
                return

        except Exception as e:
            import traceback

            print("ERROR TRACE:", traceback.format_exc())
            await __event_emitter__(
                {
                    "type": "notification",
                    "data": {"type": "error", "content": "Error: {}".format(str(e))},
                }
            )
        return {"status": "complete"}
