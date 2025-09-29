"""
title: Share to Flywheel
author: Nicholas Vincent
version: 0.5
required_open_webui_version: 0.5.0
description: Share conversations via Pull Requests for community moderation
icon_url: data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik00IDEydjdjMCAuNTUuNDUgMSAxIDFoMTRjLjU1IDAgMS0uNDUgMS0xdi03Ii8+PHBhdGggZD0iTTEyIDE2VjMiLz48cGF0aCBkPSJNOCA3bDQtNCA0IDQiLz48L3N2Zz4=
"""

import io
import json
import re
import secrets
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple
from typing_extensions import TypedDict

from pydantic import BaseModel, Field
from fastapi.responses import HTMLResponse


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------
HUGGINGFACE_TOKENS_DOC_URL = "https://huggingface.co/docs/hub/en/security-tokens"
HUGGINGFACE_TOKENS_SETTINGS_URL = "https://huggingface.co/settings/tokens"
HUGGINGFACE_DATASET_DISCUSSION_URL = (
    "https://huggingface.co/datasets/{repo}/discussions/{num}"
)
DATALICENSES_URL = "https://datalicenses.org"
DEFAULT_FAQ_URL = "https://example.com/flywheel-faq"
DEFAULT_PRIVACY_POLICY_URL = "https://example.com/privacy"
PUBLICAI_GITHUB_URL = "https://github.com/publicai"

TRIM_MARKERS: Tuple[str, str] = (
    "# Share Chat Publicly (Hugging Face)",
    "# Ready to Share:",
)

PUBLIC_DATA_WARNING = "<strong>⚠️ You are about to share a chat publicly.</strong>"


# ---------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------
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
    response_labels: Dict[str, Literal["good", "bad"]]


def validate_contribution(c: Dict[str, Any]) -> Contribution:
    required = {
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
    missing = required - set(c.keys())
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


# ---------------------------------------------------------------------
# Privacy patterns
# ---------------------------------------------------------------------
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
    "iban": r"\b(?:AL|AD|AT|AZ|BH|BE|BA|BR|BG|CR|HR|CY|CZ|DK|DO|EE|FO|FI|FR|GE|DE|GI|GR|GL|GT|HU|IS|IE|IL|IT|JO|KZ|KW|LV|LB|LI|LT|LU|MT|MR|MU|MC|MD|ME|NL|NO|PK|PS|PL|PT|QA|RO|SM|SA|RS|SK|SI|ES|SE|CH|TN|TR|AE|GB|VG|XK)\d{2}[A-Z0-9]{4,30}\b",
    "us_passport": r"\b(?:[0-9]{9}|[A-Z][0-9]{8})\b",
    "ein": r"\b\d{2}-\d{7}\b",
    "medicare": r"\b[A-Z0-9]{4}-[A-Z0-9]{3}-[A-Z0-9]{4}\b",
    "bitcoin_address": r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b",
    "ethereum_address": r"\b0x[a-fA-F0-9]{40}\b",
}


# ---------------------------------------------------------------------
# Tools implementation
# ---------------------------------------------------------------------
class Tools:
    def __init__(self):
        self.valves = self.Valves()
        self.citation = False  # custom citations disabled by default
        self.db_path = str(Path.home() / ".open-webui" / "webui.db")
        self.recent_submissions: Dict[str, Tuple[datetime, str]] = {}

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
        allow_no_chat_id_submission: bool = Field(
            default=False,
            description=(
                "Safer default: If no chat_id is detected, force simulation only. Set True to allow real submits without chat_id."
            ),
        )
        service_base_url: str = Field(
            default="http://127.0.0.1:8765",
            description="External Flywheel service base URL (for interactive iframe)",
        )
        faq_url: str = Field(default=DEFAULT_FAQ_URL, description="Data FAQ")
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
                "How your name appears: anonymous = least linkability; "
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
                "High‑level intent for data use. Will be translated as standards mature (see datalicenses.org)."
            ),
        )
        license_intent_note: str = Field(
            default="",
            description=(
                "Optional note to clarify your licensing intent (e.g., reciprocity definition)."
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
                f"Your Hugging Face write token (never published). Create/manage at {HUGGINGFACE_TOKENS_DOC_URL}"
            ),
        )

    # ------------------------------------------------------------------
    # Dedup guard
    # ------------------------------------------------------------------
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
                    f'This chat was shared {seconds_ago} seconds ago. <a href="{pr_url}">View PR #{pr_number}</a>',
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
        out = dict(contribution)
        out.pop("source_chat_id", None)
        if out.get("content_hash") and not out.get("content_hash_note"):
            out["content_hash_note"] = (
                "Shared to help detect duplicates and verify integrity without exposing raw text."
            )
        return out

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

        cur.execute("SELECT tag_name FROM chatidtag WHERE chat_id = ?", (chat_id,))
        tags_rows = [r["tag_name"] for r in cur.fetchall() if r and r["tag_name"]]

        try:
            raw_meta = chat_row.get("meta")
            meta_json = (
                json.loads(raw_meta) if isinstance(raw_meta, str) else (raw_meta or {})
            )
        except Exception:
            meta_json = {}
        meta_tags = []
        try:
            maybe_tags = (meta_json or {}).get("tags")
            if isinstance(maybe_tags, list):
                meta_tags = [t for t in maybe_tags if isinstance(t, str)]
        except Exception:
            meta_tags = []

        try:
            raw_chat = chat_row.get("chat")
            chat_json = (
                json.loads(raw_chat) if isinstance(raw_chat, str) else (raw_chat or {})
            )
        except Exception:
            chat_json = {}
        messages = chat_json.get("messages", []) if isinstance(chat_json, dict) else []
        chat_tags = []
        try:
            maybe_ctags = (
                (chat_json or {}).get("tags") if isinstance(chat_json, dict) else []
            )
            if isinstance(maybe_ctags, list):
                chat_tags = [t for t in maybe_ctags if isinstance(t, str)]
        except Exception:
            chat_tags = []

        tags = [*tags_rows, *meta_tags, *chat_tags]

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
        self, user_valves: "Tools.UserValves", user_obj: Dict[str, Any]
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

            api = HfApi()
            file_path = f"contributions/{contribution['id']}.json"
            safe_contrib = self._sanitize_contribution_for_export(contribution)
            json_content = json.dumps(safe_contrib, indent=2, ensure_ascii=False)

            pr_title = f"[{contribution['sharing_reason']}] Contribution ({contribution.get('attribution', 'anonymous')})"
            pr_description = (
                "## Contribution Details\n\n"
                f"**Assessment**: {contribution['sharing_reason']} (`{contribution['sharing_tag']}`)\n"
                f"**Messages**: {len(contribution['clean_content'])}\n"
                f"**Attribution (declared)**: {contribution.get('attribution', 'anonymous')}\n\n"
                f"**Licensing Intent (declarative)**: {contribution.get('license_intent', 'unspecified')}\n"
                f"**Licensing Note**: {contribution.get('license_intent_note', '—') or '—'}\n"
                f"**Contributor Thoughts (AI)**:\n{contribution.get('ai_thoughts', '—') or '—'}\n"
                f"**Content Hash**: `{contribution.get('content_hash', 'N/A')}`\n"
                f"**Submitted**: {contribution['contributed_at']}\n\n"
                f"**Attribution Mode**: {contribution.get('attribution_mode', 'anonymous')}\n"
                f"**Submitting via**: {contribution.get('submit_via', 'app account')}\n"
                f"**Verification**: {json.dumps(contribution.get('verification', {}), ensure_ascii=False)}\n"
                f"**Tags**: {', '.join('`'+t+'`' for t in contribution['all_tags'][:10])}\n\n"
                "Submitted via the Flywheel OpenWebUI plugin.\n"
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
            return {"success": False, "error": f"{type(e).__name__}: {e}"}

    def _clean_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

    def _map_response_labels(
        self,
        raw_messages: List[Dict[str, Any]],
        clean_messages: List[Dict[str, Any]],
        feedback_items: List[Dict[str, Any]],
    ) -> Dict[str, Literal["good", "bad"]]:
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
            mid = meta.get("message_id") or data.get("message_id")
            if isinstance(mid, str) and mid in id_to_clean:
                key = str(id_to_clean[mid])
                if key not in labels:
                    labels[key] = label
                continue
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
    # HTML helpers
    # ------------------------------------------------------------------
    def _html_page(self, title: str, body_html: str) -> HTMLResponse:
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
    .grid-1 {{ display: grid; grid-template-columns: 1fr; gap: 16px; }}
    code, pre {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 8px; overflow: auto; }}
    details > summary {{ cursor: pointer; margin-bottom: 8px; }}
    .btns {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .btn {{ background: #111827; color: #fff; border: 0; border-radius: 6px; padding: 8px 12px; cursor: default; opacity: .7; }}
    .btn.secondary {{ background: #6b7280; }}
    .tag {{ display: inline-block; background: #eef2ff; color: #3730a3; padding: 2px 8px; border-radius: 999px; margin: 0 6px 6px 0; font-size: 12px; }}
  </style>
  
</head>
<body>
  <div class=\"container\">{body_html}</div>
</body>
</html>
"""
        return HTMLResponse(content=html, headers={"Content-Disposition": "inline"})

    def _render_preview_html(
        self,
        chat: Dict[str, Any],
        clean_messages: List[Dict[str, Any]],
        contribution: Contribution,
        privacy: Dict[str, Any],
        submit_via: str,
    ) -> HTMLResponse:
        privacy_status = (
            "✅ No obvious personal data detected"
            if not privacy["has_issues"]
            else "⚠️ Potential personal data detected (expand 'Details')"
        )
        privacy_note = ""
        if privacy["has_issues"]:
            types_str = ", ".join(privacy["types_found"][:3])
            privacy_note = f"<p><strong>Privacy Warning</strong>: Possible {types_str}. Review before sharing.</p>"

        norm_tags = self._norm_tags(chat["tags"]) or []
        tags_html = (
            "".join(f"<span class='tag'>{t}</span>" for t in norm_tags)
            or "<span class='muted'>none</span>"
        )

        export_contribution = self._sanitize_contribution_for_export(contribution)
        json_str = json.dumps(export_contribution, indent=2, ensure_ascii=False)

        grabbed_feedback = [
            {
                "id": it.get("id"),
                "type": it.get("type"),
                "rating": (it.get("data") or {}).get("rating"),
                "created_at": it.get("created_at"),
            }
            for it in chat["feedback_items"][:5]
        ]

        body = f"""
<div class='card warning'>
  {PUBLIC_DATA_WARNING}
  <div class='muted' style='margin-top:6px;'>Data FAQ: <a href='{self.valves.faq_url}' target='_blank'>{self.valves.faq_url}</a> • Privacy Policy: <a href='{self.valves.privacy_policy_url}' target='_blank'>{self.valves.privacy_policy_url}</a></div>
</div>

<div class='card'>
  <h2 style='margin:0 0 8px 0;'>Ready to Share: "{chat['title']}"</h2>
  <div><strong>Assessment</strong>: {contribution['sharing_reason']} (<code>{contribution['sharing_tag']}</code>) • <strong>Messages</strong>: {len(clean_messages)} • <strong>Intent</strong>: {contribution['license_intent']} • <strong>Display</strong>: {contribution['attribution']} • <strong>Submitting via</strong>: {submit_via}</div>
  <div style='margin-top:10px;'><strong>Privacy</strong>: {privacy_status}</div>
  {privacy_note}
  <details style='margin-top:10px;'>
    <summary>Details</summary>
    <div style='margin:8px 0;'>
      <div><strong>Tags</strong>: {tags_html}</div>
      <div style='margin-top:6px;'><strong>Feedback</strong>: 👍 {chat['feedback_counts'].get('good',0)} • 👎 {chat['feedback_counts'].get('bad',0)}</div>
      <details style='margin-top:8px;'>
        <summary>Privacy Scan (counts)</summary>
        <pre>{json.dumps(privacy, indent=2)}</pre>
      </details>
      <details style='margin-top:8px;'>
        <summary>Feedback samples (up to 5)</summary>
        <pre>{json.dumps(grabbed_feedback, indent=2, ensure_ascii=False)}</pre>
      </details>
      <details style='margin-top:8px;'>
        <summary>Share Preview JSON (exactly what will be sent)</summary>
        <pre>{json_str}</pre>
      </details>
    </div>
  </details>
  <div class='btns' style='margin-top:10px;'>
    <button class='btn' onclick=\"noop('This embedded preview is read-only. Re-run the tool with updated parameters or user valves to submit.')\">Submit</button>
    <button class='btn secondary' onclick=\"noop('Re-run the preview tool to refresh with latest tags/feedback.')\">Refresh</button>
  </div>
</div>

<div class='card muted'>
  <div><strong>How to submit</strong></div>
  <div style='margin-top:6px;'>Use the <code>share_to_flywheel_submit</code> tool with your desired settings. The preview above shows exactly what will be sent.</div>
</div>
"""
        return self._html_page("Share to Flywheel — Preview", body)

    # ------------------------------------------------------------------
    # Public tools
    # ------------------------------------------------------------------
    async def prepare_to_share(
        self,
        attribution_mode: Optional[Literal["anonymous", "pseudonym", "huggingface"]] = None,
        license_intent: Optional[
            Literal[
                "AI devs who open‑source only",
                "AI devs who contribute back to the ecosystem",
                "Public bodies only",
                "Research and nonprofit only",
                "Commercial use allowed with reciprocity",
                "No AI training use",
                "Ask first / case‑by‑case",
            ]
        ] = None,
        license_intent_note: Optional[str] = None,
        ai_thoughts: Optional[str] = None,
        hf_user_token: Optional[str] = None,
        __user__: Optional[dict] = None,
        __event_emitter__=None,
        __metadata__: Optional[dict] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
    ) -> HTMLResponse:
        """
        Brings up the interactive HTML panel to review and adjust contribution details.
        This is a UI-only helper (no submit); use share_chat_publicly to submit after review.
        """
        # Build iframe to external service for interactive UI
        inferred_chat_id = (
            (__metadata__ or {}).get("chat_id")
            or (((__metadata__ or {}).get("chat") or {}).get("id") if isinstance((__metadata__ or {}).get("chat"), dict) else None)
            or (__metadata__ or {}).get("id")
            or (__metadata__ or {}).get("chatId")
        )
        params = []
        if inferred_chat_id:
            params.append(f"chat_id={inferred_chat_id}")
        if attribution_mode:
            params.append(f"attribution_mode={attribution_mode}")
        if license_intent:
            params.append(f"license_intent={license_intent}")
        if license_intent_note is not None:
            from urllib.parse import quote
            params.append(f"license_intent_note={quote(license_intent_note)}")
        if ai_thoughts is not None:
            from urllib.parse import quote
            params.append(f"ai_thoughts={quote(ai_thoughts)}")
        query = ("?" + "&".join(params)) if params else ""
        iframe_url = f"{self.valves.service_base_url}/flywheel/prepare{query}"

        html = f"""
<!doctype html>
<html><head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Prepare to Share</title>
  <style>body,html{{height:100%;margin:0}} .wrap{{height:100%;}} iframe{{width:100%;height:80vh;border:0}}</style>
</head>
<body>
  <div class=\"wrap\">
    <iframe src=\"{iframe_url}\" title=\"Flywheel Share\"></iframe>
  </div>
</body></html>
"""
        return HTMLResponse(content=html, headers={"Content-Disposition": "inline"})
    async def share_publicly(
        self,
        action: Literal["preview", "submit"] = "preview",
        attribution_mode: Optional[Literal["anonymous", "pseudonym", "huggingface"]] = None,
        license_intent: Optional[
            Literal[
                "AI devs who open‑source only",
                "AI devs who contribute back to the ecosystem",
                "Public bodies only",
                "Research and nonprofit only",
                "Commercial use allowed with reciprocity",
                "No AI training use",
                "Ask first / case‑by‑case",
            ]
        ] = None,
        license_intent_note: Optional[str] = None,
        ai_thoughts: Optional[str] = None,
        hf_user_token: Optional[str] = None,
        __user__: Optional[dict] = None,
        __event_emitter__=None,
        __metadata__: Optional[dict] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
    ) -> HTMLResponse:
        """
        Share this chat publicly to the Flywheel dataset.

        Natural usage examples:
        - "Share this chat publicly" → action="preview" (default)
        - "Submit this chat publicly now" → action="submit"

        If called inside a chat, the chat id is auto-detected; otherwise pass chat_id via share_to_flywheel_* methods.
        """
        if action == "submit":
            return await self.share_to_flywheel_submit(
                chat_id=None,
                attribution_mode=attribution_mode,
                license_intent=license_intent,
                license_intent_note=license_intent_note,
                ai_thoughts=ai_thoughts,
                hf_user_token=hf_user_token,
                __user__=__user__,
                __event_emitter__=__event_emitter__,
                __metadata__=__metadata__,
                __messages__=__messages__,
            )
        else:
            return await self.share_to_flywheel_preview(
                chat_id=None,
                attribution_mode=attribution_mode,
                license_intent=license_intent,
                license_intent_note=license_intent_note,
                ai_thoughts=ai_thoughts,
                hf_user_token=hf_user_token,
                __user__=__user__,
                __event_emitter__=__event_emitter__,
                __metadata__=__metadata__,
                __messages__=__messages__,
        )

    async def share_this_chat(
        self,
        confirm: bool = False,
        attribution_mode: Optional[Literal["anonymous", "pseudonym", "huggingface"]] = None,
        license_intent: Optional[
            Literal[
                "AI devs who open‑source only",
                "AI devs who contribute back to the ecosystem",
                "Public bodies only",
                "Research and nonprofit only",
                "Commercial use allowed with reciprocity",
                "No AI training use",
                "Ask first / case‑by‑case",
            ]
        ] = None,
        license_intent_note: Optional[str] = None,
        ai_thoughts: Optional[str] = None,
        hf_user_token: Optional[str] = None,
        __user__: Optional[dict] = None,
        __event_emitter__=None,
        __metadata__: Optional[dict] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
    ) -> HTMLResponse:
        """
        Convenience alias: preview unless confirm=True, then submit.
        Natural usage examples:
        - "Preview sharing this chat"
        - "Share this chat (confirm)" → confirm=True
        """
        if confirm:
            return await self.share_to_flywheel_submit(
                chat_id=None,
                attribution_mode=attribution_mode,
                license_intent=license_intent,
                license_intent_note=license_intent_note,
                ai_thoughts=ai_thoughts,
                hf_user_token=hf_user_token,
                __user__=__user__,
                __event_emitter__=__event_emitter__,
                __metadata__=__metadata__,
                __messages__=__messages__,
            )
        return await self.share_to_flywheel_preview(
            chat_id=None,
            attribution_mode=attribution_mode,
            license_intent=license_intent,
            license_intent_note=license_intent_note,
            ai_thoughts=ai_thoughts,
            hf_user_token=hf_user_token,
            __user__=__user__,
            __event_emitter__=__event_emitter__,
            __metadata__=__metadata__,
            __messages__=__messages__,
        )

    async def share_chat_publicly(
        self,
        require_confirmation: bool = True,
        attribution_mode: Optional[Literal["anonymous", "pseudonym", "huggingface"]] = None,
        license_intent: Optional[
            Literal[
                "AI devs who open‑source only",
                "AI devs who contribute back to the ecosystem",
                "Public bodies only",
                "Research and nonprofit only",
                "Commercial use allowed with reciprocity",
                "No AI training use",
                "Ask first / case‑by‑case",
            ]
        ] = None,
        license_intent_note: Optional[str] = None,
        ai_thoughts: Optional[str] = None,
        hf_user_token: Optional[str] = None,
        __user__: Optional[dict] = None,
        __event_emitter__=None,
        __event_call__=None,
        __metadata__: Optional[dict] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
    ) -> HTMLResponse:
        """
        One-call flow: builds preview, asks for confirmation, then submits.
        - Works best with Function Calling = "default" for richer preview messaging.
        - In "native" mode, uses confirmation and returns receipts, but streaming preview may be limited.
        """
        # Detect chat id (with several fallbacks)
        inferred_chat_id = (
            (__metadata__ or {}).get("chat_id")
            or (((__metadata__ or {}).get("chat") or {}).get("id") if isinstance((__metadata__ or {}).get("chat"), dict) else None)
            or (__metadata__ or {}).get("id")
            or (__metadata__ or {}).get("chatId")
        )

        # Load user valves + overrides
        user_valves: Tools.UserValves = (
            (__user__ or {}).get("valves")
            if isinstance((__user__ or {}).get("valves"), Tools.UserValves)
            else self.UserValves()
        )
        if attribution_mode:
            user_valves.attribution_mode = attribution_mode
        if license_intent:
            user_valves.license_intent = license_intent  # type: ignore[assignment]
        if license_intent_note is not None:
            user_valves.license_intent_note = license_intent_note
        if ai_thoughts is not None:
            user_valves.ai_thoughts = ai_thoughts
        if hf_user_token is not None:
            user_valves.hf_user_token = hf_user_token

        if not user_valves.public_sharing_available:
            faq_html = f"""
<div class='card'>
  <h2>Share Chat Publicly (Hugging Face) — Setup</h2>
  <p>Enable public sharing first:</p>
  <ol>
    <li>Controls → Valves → Functions → Sharing</li>
    <li>Toggle <strong>Public Sharing Available</strong> ON</li>
    <li>Choose how you show up (Anonymous / Pseudonym / Hugging Face)</li>
    <li>Pick your <strong>Data Licensing Intent</strong> (see <a target='_blank' href='{DATALICENSES_URL}'>datalicenses.org</a>)</li>
  </ol>
  <p class='muted'>Docs: <a href='{HUGGINGFACE_TOKENS_DOC_URL}' target='_blank'>HF tokens</a> • <a href='{HUGGINGFACE_TOKENS_SETTINGS_URL}' target='_blank'>Token settings</a> • FAQ: <a href='{self.valves.faq_url}' target='_blank'>{self.valves.faq_url}</a> • Privacy: <a href='{self.valves.privacy_policy_url}' target='_blank'>{self.valves.privacy_policy_url}</a></p>
</div>
"""
            return self._html_page("Share to Flywheel — Setup", faq_html)

        try:
            if __event_emitter__:
                await __event_emitter__({"type": "status", "data": {"description": "Building preview...", "done": False}})

            if inferred_chat_id:
                chat = self._get_full_chat_data(str(inferred_chat_id))
            else:
                # Fallback: build from in-memory messages
                msgs = __messages__ or []
                chat = {
                    "chat_id": None,
                    "title": "Untitled Chat",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "messages": msgs,
                    "tags": [],
                    "meta": {},
                    "feedback_items": [],
                    "feedback_counts": {"good": 0, "bad": 0},
                }
                if __event_emitter__:
                    await __event_emitter__({
                        "type": "notification",
                        "data": {"type": "warning", "content": "Could not detect chat id; using current messages only (no tags/feedback)."}
                    })
            clean_messages = self._clean_messages(chat["messages"])

            if len(clean_messages) < self.valves.min_messages:
                return self._html_page(
                    "Share to Flywheel — Too Short",
                    f"<div class='card'><strong>Too short.</strong> Minimum {self.valves.min_messages} messages required.</div>",
                )
            if len(clean_messages) > self.valves.max_messages:
                return self._html_page(
                    "Share to Flywheel — Too Long",
                    f"<div class='card'><strong>Too long.</strong> Maximum {self.valves.max_messages} messages. Consider splitting.</div>",
                )

            privacy = self._check_privacy(clean_messages)
            attribution, verification = self._resolve_attribution(user_valves, __user__ or {})
            sharing_tag, reason = self._compute_sharing_reason(chat["feedback_counts"])
            response_labels = self._map_response_labels(chat["messages"], clean_messages, chat["feedback_items"])

            contrib_id = f"contrib_{secrets.token_urlsafe(8)}"
            messages_hash = self._hash_messages(clean_messages)
            contribution: Contribution = validate_contribution(
                {
                    "id": contrib_id,
                    "title": chat["title"],
                    "clean_content": clean_messages,
                    "sharing_reason": reason,
                    "sharing_tag": sharing_tag,
                    "all_tags": self._norm_tags(chat["tags"]),
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

            export_contribution = self._sanitize_contribution_for_export(contribution)
            preview_json = json.dumps(export_contribution, indent=2, ensure_ascii=False)

            # Concise confirmation message (avoid giant dialog). Full HTML preview is optional via dedicated preview tool.
            preview_lines = [
                f"Assessment: {reason} ({sharing_tag})",
                f"Messages: {len(clean_messages)}",
                f"Intent: {contribution['license_intent']}",
                f"Display: {contribution['attribution']}",
                ("Privacy: ⚠️ potential issues" if privacy["has_issues"] else "Privacy: ✅ none detected"),
            ]
            faq_snippet = f"FAQ: {self.valves.faq_url} • Privacy: {self.valves.privacy_policy_url}"
            confirm_message = (
                "\n".join(preview_lines)
                + "\n\nProceed to submit this contribution?\n\n"
                + faq_snippet
            )

            proceed = True
            if require_confirmation and __event_call__:
                try:
                    result = await __event_call__({
                        "type": "confirmation",
                        "data": {
                            "message": confirm_message,
                            "confirm_text": "Submit",
                            "cancel_text": "Cancel",
                        },
                    })
                    proceed = bool((result or {}).get("confirmed", True))
                except Exception:
                    proceed = False

            if require_confirmation and not proceed:
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "Submission canceled", "done": True}})
                return self._html_page(
                    "Share to Flywheel — Canceled",
                    "<div class='card'><strong>Canceled.</strong> You chose not to submit.</div>",
                )

            # Submission path
            use_user_token = (
                user_valves.attribution_mode == "huggingface" and (user_valves.hf_user_token or "").strip()
            )
            have_app_token = bool(self.valves.default_hf_token and self.valves.dataset_repo)
            hf_token = user_valves.hf_user_token if use_user_token else self.valves.default_hf_token
            submit_via = (
                "your Hugging Face account" if use_user_token else ("app account" if have_app_token else "simulation")
            )

            # If no chat_id and not permitted, force simulation regardless of tokens
            force_sim = (inferred_chat_id is None) and (not self.valves.allow_no_chat_id_submission)
            if force_sim and __event_emitter__:
                await __event_emitter__({
                    "type": "notification",
                    "data": {"type": "warning", "content": "No chat_id detected. For safety, submitting in Test Mode only."}
                })

            # Preflight when making real PRs
            if not force_sim and (use_user_token or have_app_token) and self.valves.sanity_check_repo:
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "Running preflight checks...", "done": False}})
                pf = self._hf_preflight(hf_token)
                if not pf.get("ok"):
                    if __event_emitter__:
                        await __event_emitter__({"type": "notification", "data": {"type": "error", "content": f"Preflight checks failed: {pf.get('errors')}"}})
                    return self._html_page(
                        "Share to Flywheel — Preflight Failed",
                        f"<div class='card'><strong>Preflight failed</strong>: {json.dumps(pf, ensure_ascii=False)}</div>",
                    )

            # Simulate if forced or no token
            if force_sim or not (use_user_token or have_app_token):
                mock_pr_number = 1234
                mock_pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(repo=self.valves.dataset_repo, num=mock_pr_number)
                body = f"""
<div class='card'>
  <h2>✅ Test Mode: PR Preview</h2>
  <ol>
    <li><strong>Pull Request</strong>: #{mock_pr_number}</li>
    <li><strong>Location</strong>: <a href='{mock_pr_url}' target='_blank'>{self.valves.dataset_repo}</a></li>
    <li><strong>Status</strong>: Awaiting review</li>
  </ol>
  <div><strong>Contribution</strong></div>
  <ul>
    <li>ID: <code>{contribution['id']}</code></li>
    <li>Assessment: {contribution['sharing_reason']}</li>
    <li>Messages: {len(contribution['clean_content'])}</li>
    <li>Licensing Intent: {contribution['license_intent']}</li>
    <li>Licensing Note: {contribution['license_intent_note'] or '—'}</li>
    <li>Contributor Thoughts (AI): {contribution['ai_thoughts'] or '—'}</li>
    <li>Submitting via: {submit_via}</li>
    <li>Contributor Display: {contribution['attribution']}</li>
  </ul>
</div>
"""
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "Complete", "done": True}})
                return self._html_page("Share to Flywheel — Test Mode", body)

            # Real PR
            if __event_emitter__:
                await __event_emitter__({"type": "status", "data": {"description": "Creating pull request...", "done": False}})
            result = self._create_pull_request(contribution, hf_token, self.valves.dataset_repo)
            if result.get("success"):
                pr_number = result.get("pr_number")
                pr_url = result.get("pr_url")
                try:
                    if isinstance(pr_number, int):
                        self._record_submission(chat_id, pr_number)
                except Exception:
                    pass
                body = f"""
<div class='card'>
  <h2>Contribution sent! Thank you!</h2>
  <p><strong>Contribution #{pr_number}</strong>: <a href='{pr_url}' target='_blank'>View on Hugging Face</a></p>
  <ul>
    <li>Assessment: {contribution['sharing_reason']}</li>
    <li>Messages: {len(contribution['clean_content'])}</li>
    <li>Licensing Intent: {contribution['license_intent']}</li>
    <li>Licensing Note: {contribution['license_intent_note'] or '—'}</li>
    <li>Contributor Thoughts (AI): {contribution['ai_thoughts'] or '—'}</li>
    <li>Submitting via: {submit_via}</li>
    <li>Contributor Display: {contribution['attribution']}</li>
  </ul>
</div>
"""
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "Complete", "done": True}})
                return self._html_page("Share to Flywheel — Sent", body)
            else:
                err = result.get("error", "Unknown error")
                if __event_emitter__:
                    await __event_emitter__({"type": "notification", "data": {"type": "error", "content": f"Failed to create PR: {err}"}})
                return self._html_page(
                    "Share to Flywheel — Error",
                    f"<div class='card'><strong>Failed to create PR:</strong> {err}</div>",
                )

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__({"type": "notification", "data": {"type": "error", "content": f"Error: {type(e).__name__}: {e}"}})
            return self._html_page(
                "Share to Flywheel — Error",
                f"<div class='card'><strong>Error:</strong> {type(e).__name__}: {e}</div>",
            )
    async def share_to_flywheel_preview(
        self,
        chat_id: Optional[str] = None,
        attribution_mode: Optional[
            Literal["anonymous", "pseudonym", "huggingface"]
        ] = None,
        license_intent: Optional[
            Literal[
                "AI devs who open‑source only",
                "AI devs who contribute back to the ecosystem",
                "Public bodies only",
                "Research and nonprofit only",
                "Commercial use allowed with reciprocity",
                "No AI training use",
                "Ask first / case‑by‑case",
            ]
        ] = None,
        license_intent_note: Optional[str] = None,
        ai_thoughts: Optional[str] = None,
        hf_user_token: Optional[str] = None,
        __user__: Optional[dict] = None,
        __event_emitter__=None,
        __metadata__: Optional[dict] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
    ) -> HTMLResponse:
        """
        Builds a rich HTML preview of the contribution with current settings.
        Returns an embeddable HTML preview (read-only). Use share_to_flywheel_submit to send.
        :param chat_id: The OpenWebUI chat id to share.
        :param attribution_mode: Override of user valves attribution mode.
        :param license_intent: Override of user valves licensing intent.
        :param license_intent_note: Optional note for licensing intent.
        :param ai_thoughts: Optional contributor thoughts.
        :param hf_user_token: Optional Hugging Face write token for user attribution.
        """
        inferred_chat_id = chat_id or (
            (__metadata__ or {}).get("chat_id")
            or (((__metadata__ or {}).get("chat") or {}).get("id") if isinstance((__metadata__ or {}).get("chat"), dict) else None)
            or (__metadata__ or {}).get("id")
            or (__metadata__ or {}).get("chatId")
        )

        # Load valves from user with overrides
        user_valves: Tools.UserValves = (
            (__user__ or {}).get("valves")
            if isinstance((__user__ or {}).get("valves"), Tools.UserValves)
            else self.UserValves()
        )
        if attribution_mode:
            user_valves.attribution_mode = attribution_mode
        if license_intent:
            user_valves.license_intent = license_intent  # type: ignore[assignment]
        if license_intent_note is not None:
            user_valves.license_intent_note = license_intent_note
        if ai_thoughts is not None:
            user_valves.ai_thoughts = ai_thoughts
        if hf_user_token is not None:
            user_valves.hf_user_token = hf_user_token

        if not user_valves.public_sharing_available:
            setup = f"""
<div class='card'>
  <h2>Share Chat Publicly (Hugging Face)</h2>
  <ol>
    <li>Controls (top right) → Valves → Functions → Sharing</li>
    <li>Toggle "Public Sharing Available" ON (Green)</li>
    <li>Choose how you show up: Anonymous, Deterministic Pseudonym, or your Hugging Face account (requires a write token; learn more: <a href='{HUGGINGFACE_TOKENS_DOC_URL}' target='_blank'>docs</a>)</li>
    <li>Choose a Data Licensing Intent. See <a href='{DATALICENSES_URL}' target='_blank'>datalicenses.org</a>.</li>
    <li>Optional: Link your Hugging Face account to author PRs as you. Create a short‑lived write token at <a href='{HUGGINGFACE_TOKENS_SETTINGS_URL}' target='_blank'>settings</a>.</li>
  </ol>
  <div class='muted'>Data FAQ: <a href='{self.valves.faq_url}' target='_blank'>{self.valves.faq_url}</a> • Privacy Policy: <a href='{self.valves.privacy_policy_url}' target='_blank'>{self.valves.privacy_policy_url}</a></div>
</div>
"""
            return self._html_page("Share to Flywheel — Setup", setup)

        try:
            if inferred_chat_id:
                chat = self._get_full_chat_data(str(inferred_chat_id))
            else:
                msgs = __messages__ or []
                chat = {
                    "chat_id": None,
                    "title": "Untitled Chat",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "messages": msgs,
                    "tags": [],
                    "meta": {},
                    "feedback_items": [],
                    "feedback_counts": {"good": 0, "bad": 0},
                }
                if __event_emitter__:
                    await __event_emitter__({
                        "type": "notification",
                        "data": {"type": "warning", "content": "Could not detect chat id; using current messages only (no tags/feedback)."}
                    })
            clean_messages = self._clean_messages(chat["messages"])

            if len(clean_messages) < self.valves.min_messages:
                return self._html_page(
                    "Share to Flywheel — Too Short",
                    f"<div class='card'><strong>Too short.</strong> Minimum {self.valves.min_messages} messages required.</div>",
                )
            if len(clean_messages) > self.valves.max_messages:
                return self._html_page(
                    "Share to Flywheel — Too Long",
                    f"<div class='card'><strong>Too long.</strong> Maximum {self.valves.max_messages} messages. Consider splitting.</div>",
                )

            privacy = self._check_privacy(clean_messages)
            attribution, verification = self._resolve_attribution(
                user_valves, __user__ or {}
            )
            sharing_tag, reason = self._compute_sharing_reason(chat["feedback_counts"])

            contrib_id = f"contrib_{secrets.token_urlsafe(8)}"
            messages_hash = self._hash_messages(clean_messages)
            response_labels = self._map_response_labels(
                chat["messages"], clean_messages, chat["feedback_items"]
            )

            contribution: Contribution = validate_contribution(
                {
                    "id": contrib_id,
                    "title": chat["title"],
                    "clean_content": clean_messages,
                    "sharing_reason": reason,
                    "sharing_tag": sharing_tag,
                    "all_tags": self._norm_tags(chat["tags"]),
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

            use_user_token = (
                user_valves.attribution_mode == "huggingface"
                and (user_valves.hf_user_token or "").strip()
            )
            have_app_token = bool(
                self.valves.default_hf_token and self.valves.dataset_repo
            )
            submit_via = (
                "your Hugging Face account"
                if use_user_token
                else ("app account" if have_app_token else "simulation")
            )

            return self._render_preview_html(
                chat, clean_messages, contribution, privacy, submit_via
            )

        except Exception as e:
            return self._html_page(
                "Share to Flywheel — Error",
                f"<div class='card'><strong>Error:</strong> {type(e).__name__}: {e}</div>",
            )

    async def share_to_flywheel_submit(
        self,
        chat_id: Optional[str] = None,
        attribution_mode: Optional[
            Literal["anonymous", "pseudonym", "huggingface"]
        ] = None,
        license_intent: Optional[
            Literal[
                "AI devs who open‑source only",
                "AI devs who contribute back to the ecosystem",
                "Public bodies only",
                "Research and nonprofit only",
                "Commercial use allowed with reciprocity",
                "No AI training use",
                "Ask first / case‑by‑case",
            ]
        ] = None,
        license_intent_note: Optional[str] = None,
        ai_thoughts: Optional[str] = None,
        hf_user_token: Optional[str] = None,
        __user__: Optional[dict] = None,
        __event_emitter__=None,
        __metadata__: Optional[dict] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
    ) -> HTMLResponse:
        """
        Submits the contribution. Recomputes tags/feedback/messages just-in-time.
        Returns an HTML receipt (or simulated preview if no tokens available).
        :param chat_id: The OpenWebUI chat id to share.
        :param attribution_mode: Override of user valves attribution mode.
        :param license_intent: Override of user valves licensing intent.
        :param license_intent_note: Optional note for licensing intent.
        :param ai_thoughts: Optional contributor thoughts.
        :param hf_user_token: Optional Hugging Face write token for user attribution.
        """
        if __event_emitter__:
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {"description": "Preparing submission...", "done": False},
                }
            )

        inferred_chat_id = chat_id or (
            (__metadata__ or {}).get("chat_id")
            or (((__metadata__ or {}).get("chat") or {}).get("id") if isinstance((__metadata__ or {}).get("chat"), dict) else None)
            or (__metadata__ or {}).get("id")
            or (__metadata__ or {}).get("chatId")
        )

        # Load valves and apply overrides
        user_valves: Tools.UserValves = (
            (__user__ or {}).get("valves")
            if isinstance((__user__ or {}).get("valves"), Tools.UserValves)
            else self.UserValves()
        )
        if attribution_mode:
            user_valves.attribution_mode = attribution_mode
        if license_intent:
            user_valves.license_intent = license_intent  # type: ignore[assignment]
        if license_intent_note is not None:
            user_valves.license_intent_note = license_intent_note
        if ai_thoughts is not None:
            user_valves.ai_thoughts = ai_thoughts
        if hf_user_token is not None:
            user_valves.hf_user_token = hf_user_token

        # Dedup guard
        is_dup, dup_msg = self._check_duplicate_submission(str(inferred_chat_id)) if inferred_chat_id else (False, "")
        if is_dup:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "notification",
                        "data": {"type": "warning", "content": dup_msg},
                    }
                )
            return self._html_page(
                "Share to Flywheel — Duplicate",
                f"<div class='card'><strong>Duplicate detected:</strong> {dup_msg}</div>",
            )

        try:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Fetching chat and latest feedback...",
                            "done": False,
                        },
                    }
                )
            if inferred_chat_id:
                chat = self._get_full_chat_data(str(inferred_chat_id))
            else:
                msgs = __messages__ or []
                chat = {
                    "chat_id": None,
                    "title": "Untitled Chat",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "messages": msgs,
                    "tags": [],
                    "meta": {},
                    "feedback_items": [],
                    "feedback_counts": {"good": 0, "bad": 0},
                }
                if __event_emitter__:
                    await __event_emitter__({
                        "type": "notification",
                        "data": {"type": "warning", "content": "Could not detect chat id; using current messages only (no tags/feedback)."}
                    })
            fresh_messages = self._clean_messages(chat["messages"])
            fresh_hash = self._hash_messages(fresh_messages)
            new_sharing_tag, new_reason = self._compute_sharing_reason(
                chat["feedback_counts"]
            )
            attribution, verification = self._resolve_attribution(
                user_valves, __user__ or {}
            )
            response_labels = self._map_response_labels(
                chat["messages"], fresh_messages, chat["feedback_items"]
            )

            contribution: Contribution = validate_contribution(
                {
                    "id": f"contrib_{secrets.token_urlsafe(8)}",
                    "title": chat["title"],
                    "clean_content": fresh_messages,
                    "sharing_reason": new_reason,
                    "sharing_tag": new_sharing_tag,
                    "all_tags": self._norm_tags(chat["tags"]),
                    "license_intent": user_valves.license_intent,
                    "license_intent_note": user_valves.license_intent_note,
                    "ai_thoughts": user_valves.ai_thoughts,
                    "attribution": attribution,
                    "attribution_mode": user_valves.attribution_mode,
                    "verification": verification,
                    "contributed_at": datetime.now(timezone.utc).isoformat(),
                    "content_hash": fresh_hash,
                    "version": "1.0.0",
                    "feedback_counts": chat["feedback_counts"],
                    "response_labels": response_labels,
                }
            )

            use_user_token = (
                user_valves.attribution_mode == "huggingface"
                and (user_valves.hf_user_token or "").strip()
            )
            have_app_token = bool(
                self.valves.default_hf_token and self.valves.dataset_repo
            )
            hf_token = (
                user_valves.hf_user_token
                if use_user_token
                else self.valves.default_hf_token
            )
            submit_via = (
                "your Hugging Face account"
                if use_user_token
                else ("app account" if have_app_token else "simulation")
            )

            # If no chat_id and not permitted, force simulation regardless of tokens
            force_sim = (inferred_chat_id is None) and (not self.valves.allow_no_chat_id_submission)
            if force_sim and __event_emitter__:
                await __event_emitter__({
                    "type": "notification",
                    "data": {"type": "warning", "content": "No chat_id detected. For safety, submitting in Test Mode only."},
                })

            # Preflight if attempting real PR
            if not force_sim and (use_user_token or have_app_token) and self.valves.sanity_check_repo:
                if __event_emitter__:
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {
                                "description": "Running preflight checks...",
                                "done": False,
                            },
                        }
                    )
                pf = self._hf_preflight(hf_token)
                if not pf.get("ok"):
                    if __event_emitter__:
                        await __event_emitter__(
                            {
                                "type": "notification",
                                "data": {
                                    "type": "error",
                                    "content": f"Preflight checks failed: {pf.get('errors')}",
                                },
                            }
                        )
                    return self._html_page(
                        "Share to Flywheel — Preflight Failed",
                        f"<div class='card'><strong>Preflight failed</strong>: {json.dumps(pf, ensure_ascii=False)}</div>",
                    )

            # Simulate if forced or no usable token
            if force_sim or not (use_user_token or have_app_token):
                mock_pr_number = 1234
                mock_pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(
                    repo=self.valves.dataset_repo, num=mock_pr_number
                )
                body = f"""
<div class='card'>
  <h2>✅ Test Mode: PR Preview</h2>
  <ol>
    <li><strong>Pull Request</strong>: #{mock_pr_number}</li>
    <li><strong>Location</strong>: <a href='{mock_pr_url}' target='_blank'>{self.valves.dataset_repo}</a></li>
    <li><strong>Status</strong>: Awaiting review</li>
  </ol>
  <div><strong>Contribution</strong></div>
  <ul>
    <li>ID: <code>{contribution['id']}</code></li>
    <li>Assessment: {contribution['sharing_reason']}</li>
    <li>Messages: {len(contribution['clean_content'])}</li>
    <li>Licensing Intent: {contribution['license_intent']}</li>
    <li>Licensing Note: {contribution['license_intent_note'] or '—'}</li>
    <li>Contributor Thoughts (AI): {contribution['ai_thoughts'] or '—'}</li>
    <li>Submitting via: {submit_via}</li>
    <li>Contributor Display: {contribution['attribution']}</li>
  </ul>
</div>
"""
                if __event_emitter__:
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": "Complete", "done": True},
                        }
                    )
                return self._html_page("Share to Flywheel — Test Mode", body)

            # Real PR path
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Creating pull request...",
                            "done": False,
                        },
                    }
                )

            result = self._create_pull_request(
                contribution, hf_token, self.valves.dataset_repo
            )
            if result.get("success"):
                pr_number = result.get("pr_number")
                pr_url = result.get("pr_url")
                # record dedup guard
                try:
                    if isinstance(pr_number, int) and inferred_chat_id:
                        self._record_submission(str(inferred_chat_id), pr_number)
                except Exception:
                    pass
                body = f"""
<div class='card'>
  <h2>Contribution sent! Thank you!</h2>
  <p><strong>Contribution #{pr_number}</strong>: <a href='{pr_url}' target='_blank'>View on Hugging Face</a></p>
  <ul>
    <li>Assessment: {contribution['sharing_reason']}</li>
    <li>Messages: {len(contribution['clean_content'])}</li>
    <li>Licensing Intent: {contribution['license_intent']}</li>
    <li>Licensing Note: {contribution['license_intent_note'] or '—'}</li>
    <li>Contributor Thoughts (AI): {contribution['ai_thoughts'] or '—'}</li>
    <li>Submitting via: {submit_via}</li>
    <li>Contributor Display: {contribution['attribution']}</li>
  </ul>
</div>
"""
                if __event_emitter__:
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": "Complete", "done": True},
                        }
                    )
                return self._html_page("Share to Flywheel — Sent", body)
            else:
                err = result.get("error", "Unknown error")
                if __event_emitter__:
                    await __event_emitter__(
                        {
                            "type": "notification",
                            "data": {
                                "type": "error",
                                "content": f"Failed to create PR: {err}",
                            },
                        }
                    )
                return self._html_page(
                    "Share to Flywheel — Error",
                    f"<div class='card'><strong>Failed to create PR:</strong> {err}</div>",
                )

        except Exception as e:
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "notification",
                        "data": {
                            "type": "error",
                            "content": f"Error: {type(e).__name__}: {e}",
                        },
                    }
                )
            return self._html_page(
                "Share to Flywheel — Error",
                f"<div class='card'><strong>Error:</strong> {type(e).__name__}: {e}</div>",
            )
