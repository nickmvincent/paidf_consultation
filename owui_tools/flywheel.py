"""
title: Share to Flywheel (Tool)
author: Nicholas Vincent
date: 2025-10-07
version: 0.3
required_open_webui_version: 0.5.0
description: Share conversations via Pull Requests for community moderation (tool-based flow)

This is a first draft of a tool-based version of the Flywheel contribution
flow. It mirrors the consent-first, preview-then-confirm workflow from the
Action version but exposes it as an OpenWebUI Tool so it can be invoked as a
natural part of the chat. It avoids direct SQL by taking tags/feedback/messages
as parameters from the caller (which can be other tools) and returns markdown
the assistant can show to the user for consent.

Consent-first: users must opt-in via user valves (public_sharing_available).
Preview first: call without confirm to get a preview + embedded JSON payload.
Confirm second: call again with confirm=true to submit (test-mode mocked).
"""

from __future__ import annotations
import hashlib
import json
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------
# Constants and templates
# ---------------------------------------------------------------------

HUGGINGFACE_TOKENS_DOC_URL = "https://huggingface.co/docs/hub/en/security-tokens"
HUGGINGFACE_TOKENS_SETTINGS_URL = "https://huggingface.co/settings/tokens"
HUGGINGFACE_DATASET_DISCUSSION_URL = (
    "https://huggingface.co/datasets/{repo}/discussions/{num}"
)
DATALICENSES_URL = "https://datalicenses.org"
DEFAULT_FAQ_URL = "https://example.com/flywheel-faq"
DEFAULT_PRIVACY_POLICY_URL = "https://example.com/privacy"

# Short markers used to trim any injected preview/setup text from the last message
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
6) Close Chat Controls once you're done, and then invoke the Share tool under your chat again!

Data FAQ: {faq_url} • Privacy Policy: {privacy_policy_url}
"""

PUBLIC_DATA_WARNING = (
    "**⚠️ You are about to share a chat publicly.**"
)

PREVIEW_HEADER = (
    "**Assessment**: **{reason}** (`{sharing_tag}`); **Messages**: {num_messages}; "
    "**Licensing Intent**: {license_intent}; **How you show up**: {attribution}; "
    "**Submitting via**: {submit_via}"
)

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
<summary>Share Preview JSON (exactly what will be sent)</summary>

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

**Next Step**: Invoke the Share tool again to {next_verb} contribute.
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

**Contribution #{pr_number}**: [View]({pr_url})

**Contribution Summary**
- Assessment: {sharing_reason}
- Messages: {num_messages}
- Licensing Intent: {license_intent}
- Licensing Note: {license_intent_note}
- Contributor Thoughts (AI): {ai_thoughts}
 - Submitting via: {submit_via}
  - Contributor Display: {attribution}
"""


# ---------------------------------------------------------------------
# Privacy patterns (counts-only heuristics)
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
    "aws_access_key": r"\b(?-i:(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16,17})\b",
    "private_key": r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----",
    "credit_card": r"\b(?:\d[-\s]?){13,19}\b",
}


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
    return c  # type: ignore[return-value]


# ---------------------------------------------------------------------
# Tool implementation (OpenWebUI Tools spec)
# ---------------------------------------------------------------------

class Tools:
    class Valves(BaseModel):
        dataset_repo: str = Field(
            default="publicai/shared-chats",
            description="Dataset repo (owner/name) for contributions",
        )
        faq_url: str = Field(default=DEFAULT_FAQ_URL, description="Data FAQ URL")
        privacy_policy_url: str = Field(
            default=DEFAULT_PRIVACY_POLICY_URL, description="Privacy policy URL"
        )
        min_messages: int = Field(
            default=2, description="Minimum messages required to share"
        )
        max_messages: int = Field(
            default=100, description="Maximum messages allowed per share"
        )
        test_mode: bool = Field(
            default=True,
            description="If true, skip real submission and return mock PR preview",
        )

    class UserValves(BaseModel):
        public_sharing_available: bool = Field(
            default=False, description="Enable public sharing workflow"
        )
        attribution_mode: Literal["anonymous", "pseudonym", "huggingface"] = Field(
            default="anonymous",
            description=(
                "How your name appears: anonymous | pseudonym | huggingface"
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
            description="High‑level intent for data use",
        )
        license_intent_note: str = Field(
            default="", description="Optional note to clarify licensing intent"
        )
        ai_thoughts: str = Field(
            default="",
            description="Optional: your thoughts about AI to include",
        )
        hf_user_token: str = Field(
            default="",
            description="Optional HF write token (never published)",
        )

    # Allow dedup checks to avoid accidental double-submits
    DUP_WINDOW_MINUTES = 5

    def __init__(self):
        self.valves = self.Valves()
        self.user_valves = self.UserValves()
        self.recent_submissions: Dict[str, Tuple[datetime, str]] = {}
    def get_user_valves(self, __user__: dict = {}) -> "Tools.UserValves":
        """Hydrate per-user valves from the session user object or defaults.

        OpenWebUI injects user valve values under __user__["valves"]. We coerce
        dicts into the pydantic model to benefit from validation and defaults.
        """
        incoming = (__user__ or {}).get("valves")
        if isinstance(incoming, self.UserValves):
            return incoming
        if isinstance(incoming, dict):
            try:
                return self.UserValves(**incoming)
            except Exception:
                pass
        return self.UserValves()

    def share_chat(
        self,
        chat_id: str,
        messages: List[Dict[str, Any]],
        confirm: bool = False,
        tags: Optional[List[str]] = None,
        feedback: Optional[List[Dict[str, Any]]] = None,
        __user__: dict = {},
    ) -> str:
        """
        Prepare or submit a Flywheel contribution for the given chat.

        Consent-first flow: call without confirm to generate a detailed preview
        (with embedded JSON) and show it to the user for review and consent.
        Only after explicit user consent, call again with confirm=true to submit.

        Do not submit without user consent. Validate privacy concerns before confirming.

        :param chat_id: The unique id of the chat being shared.
        :param messages: Recent chat messages (the model will provide these).
        :param confirm: If False (default), returns preview; if True, performs submission (test-mode mocked).
        :param tags: Optional tags associated with this chat (provided by other tools or the UI).
        :param feedback: Optional feedback items for this chat with message_id or message_index.
        :return: Markdown content describing the preview or the submission result.
        """
        user_valves = self.get_user_valves(__user__)

        if not chat_id:
            return "No chat selected."

        if not user_valves.public_sharing_available:
            return SETUP_TEMPLATE.format(
                faq_url=self.valves.faq_url,
                privacy_policy_url=self.valves.privacy_policy_url,
                hf_tokens_doc_url=HUGGINGFACE_TOKENS_DOC_URL,
                hf_tokens_settings_url=HUGGINGFACE_TOKENS_SETTINGS_URL,
                datalicenses_url=DATALICENSES_URL,
            )

        tags = tags or []
        feedback = feedback or []

        clean_messages = self._clean_messages(messages or [])
        if len(clean_messages) < self.valves.min_messages:
            return f"Too short. Minimum {self.valves.min_messages} messages required."
        if len(clean_messages) > self.valves.max_messages:
            return f"Too long. Maximum {self.valves.max_messages} messages. Consider splitting."

        # dedup
        is_dup, dup_msg = self._check_duplicate_submission(chat_id)
        if is_dup and confirm:
            return dup_msg

        # Privacy
        privacy = self._check_privacy(clean_messages)
        privacy_status = (
            "✅ No obvious personal data detected"
            if not privacy.get("has_issues")
            else "⚠️ Potential personal/sensitive data detected"
        )
        privacy_note = (
            " - please review carefully before sharing." if privacy.get("has_issues") else ""
        )

        # Feedback labels and counts
        labels = self._map_response_labels(messages or [], clean_messages, feedback)
        counts = {"good": 0, "bad": 0}
        for v in labels.values():
            counts[v] = counts.get(v, 0) + 1
        sharing_tag, sharing_reason = self._compute_sharing_reason(counts)

        # Attribution
        attribution, submit_via = self._resolve_attribution(user_valves, __user__ or {})

        # Contribution object
        contrib: Contribution = {
            "id": secrets.token_hex(6),
            "title": f"Chat {chat_id}",
            "clean_content": clean_messages,
            "sharing_reason": sharing_reason,
            "sharing_tag": sharing_tag,
            "all_tags": self._norm_tags(tags),
            "license_intent": user_valves.license_intent,
            "license_intent_note": user_valves.license_intent_note,
            "ai_thoughts": user_valves.ai_thoughts,
            "attribution": attribution,
            "attribution_mode": user_valves.attribution_mode,
            "verification": {
                "content_hash": self._hash_messages(clean_messages),
                "message_count": len(clean_messages),
            },
            "contributed_at": datetime.now(timezone.utc).isoformat(),
            "content_hash": self._hash_messages(clean_messages),
            "version": "0.2-tool",
            "feedback_counts": counts,
            "response_labels": labels,
        }

        header = PREVIEW_HEADER.format(
            reason=sharing_reason,
            sharing_tag=sharing_tag,
            num_messages=len(clean_messages),
            license_intent=user_valves.license_intent,
            attribution=attribution,
            submit_via=submit_via,
        )

        grabbed = GRABBED_SECTION_TEMPLATE.format(
            tags_line=", ".join(self._norm_tags(tags)) or "(none)",
            good=counts.get("good", 0),
            bad=counts.get("bad", 0),
            reason_upper=sharing_reason.upper(),
            sample_feedback_json=json.dumps((feedback or [])[:5], indent=2, ensure_ascii=False),
        )

        share_json = SHARE_JSON_BLOCK.format(
            json_str=json.dumps(contrib, indent=2, ensure_ascii=False)
        )

        tip_line = (
            "**Tip:** Update **tags** and **feedback** in the UI to add more detail to your contribution. "
            "We’ll auto‑grab the latest tags/feedback right before sending.\n"
        )

        privacy_block = PRIVACY_BLOCK.format(
            privacy_json=json.dumps(privacy, indent=2, ensure_ascii=False)
        )

        intent_note_block = (
            f"\n> Licensing Note: {user_valves.license_intent_note}\n"
            if user_valves.license_intent_note
            else ""
        )
        license_intent_block = f"\n- Licensing Intent: {user_valves.license_intent}\n"
        ai_thoughts_block = (
            f"- Contributor Thoughts (AI): {user_valves.ai_thoughts}\n" if user_valves.ai_thoughts else ""
        )

        preview_md = PREVIEW_TEMPLATE.format(
            title=contrib["title"],
            public_data_warning=PUBLIC_DATA_WARNING,
            tip_line=tip_line,
            faq_url=self.valves.faq_url,
            privacy_policy_url=self.valves.privacy_policy_url,
            privacy_status=privacy_status,
            privacy_note=privacy_note,
            intent_note_block=intent_note_block,
            preview_header=header,
            license_intent_block=license_intent_block,
            ai_thoughts_block=ai_thoughts_block,
            privacy_block=privacy_block,
            grabbed_section=grabbed,
            share_json_block=share_json,
            next_verb="actually",
        )

        if not confirm:
            return preview_md

        # Confirmed path (test-mode mocked)
        if self.valves.test_mode:
            pr_number = secrets.randbelow(9000) + 1000
            pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(
                repo=self.valves.dataset_repo, num=pr_number
            )
            self._record_submission(chat_id, pr_number)
            return TEST_MODE_RESULT.format(
                mock_pr_number=pr_number,
                dataset_repo=self.valves.dataset_repo,
                mock_pr_url=pr_url,
                contrib_id=contrib["id"],
                sharing_reason=sharing_reason,
                num_messages=len(clean_messages),
                license_intent=user_valves.license_intent,
                license_intent_note=user_valves.license_intent_note,
                ai_thoughts=user_valves.ai_thoughts or "(none)",
                submit_via=submit_via,
                attribution=attribution,
            )

        return "Submission path not yet wired for non-test mode."

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------
    def _norm_tags(self, tags: List[str]) -> List[str]:
        return sorted({(t or "").strip().lower() for t in tags if isinstance(t, str) and t.strip()})

    def _hash_messages(self, messages: List[Dict[str, Any]]) -> str:
        basis = []
        for m in messages:
            basis.append(
                {
                    "role": m.get("role"),
                    "content": m.get("content"),
                    "model": m.get("model"),
                    "tool_calls": m.get("tool_calls"),
                }
            )
        content = json.dumps(basis, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _deterministic_pseudonym(self, user_obj: Dict[str, Any]) -> str:
        uid = (
            (user_obj or {}).get("id")
            or (user_obj or {}).get("username")
            or (user_obj or {}).get("profile", {}).get("username")
            or "anon"
        )
        h = hashlib.sha256(str(uid).encode()).hexdigest()
        adjectives = ["swift", "calm", "bright", "clever", "brave", "curious", "quiet", "lucky", "merry", "stellar"]
        nouns = ["otter", "lynx", "falcon", "willow", "ember", "quartz", "spruce", "aurora", "delta", "river"]
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

    def _clean_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        clean: List[Dict[str, Any]] = []

        def _trim_last(content: str) -> str:
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
                content = _trim_last(content)
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

    def _detect_workflow_stage(self, messages: List[Dict[str, Any]]) -> Tuple[str, Optional[str]]:
        WORKFLOW_SCAN_DEPTH = 25
        if not messages:
            return "first_run", None
        for msg in reversed(messages[-WORKFLOW_SCAN_DEPTH:]):
            content = msg.get("content", "") or ""
            if (
                "<<<SHARE_PREVIEW_START>>>" in content
                and "<<<SHARE_PREVIEW_END>>>" in content
                and "**Next Step**: Invoke the Share tool again" in content
            ):
                return "confirm_run", content
        return "first_run", None

    def _map_response_labels(
        self,
        raw_messages: List[Dict[str, Any]],
        clean_messages: List[Dict[str, Any]],
        feedback_items: List[Dict[str, Any]],
    ) -> Dict[str, Literal["good", "bad"]]:
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

    def _compute_sharing_reason(self, counts: Dict[str, int]) -> Tuple[str, Literal["good", "bad", "mixed"]]:
        g, b = counts.get("good", 0), counts.get("bad", 0)
        if g > 0 and b == 0:
            return "dataset-good", "good"
        if b > 0 and g == 0:
            return "dataset-bad", "bad"
        return "dataset-mixed", "mixed"

    def _resolve_attribution(self, user_valves: "Tools.UserValves", user_obj: Dict[str, Any]) -> Tuple[str, str]:
        mode = user_valves.attribution_mode
        if mode == "anonymous":
            return "anonymous", "service account"
        if mode == "pseudonym":
            return self._deterministic_pseudonym(user_obj), "service account"
        # huggingface
        return "Hugging Face account", "user account"

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
        self.recent_submissions[chat_id] = (datetime.now(timezone.utc), str(pr_number))
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        self.recent_submissions = {
            cid: (ts, pr)
            for cid, (ts, pr) in self.recent_submissions.items()
            if ts > cutoff
        }


# ---------------------------------------------------------------------
# MCP service sketch (optional)
# ---------------------------------------------------------------------
"""
MCP Service (sketch)

Consider providing a lightweight MCP server exposing a modular surface used by
this tool (and other tools):

Commands:
- chats.get(chat_id): returns messages, title
- chats.tags(chat_id): returns [tags]
- feedback.list(chat_id): returns feedback items with message_id/index
- share.preview(payload): validates and returns markdown/summary
- share.submit(payload): creates commit/PR

Advantages:
- Decouples data access from the tool; no direct SQL inside the tool.
- Easier to test and evolve independently of the UI.
- Enables richer policy enforcement and logging in one place.

Implementation notes:
- Use an MCP Python server library; wire secure local access.
- Add provider adapters (OpenWebUI DB, REST API, etc.).
- Return compact, tool-friendly JSON; avoid leaking PII.
"""
