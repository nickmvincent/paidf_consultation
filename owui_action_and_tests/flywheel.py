"""
title: Share to Flywheel
author: Nicholas Vincent
version: 0.5
required_open_webui_version: 0.5.0
description: Share conversations via Pull Requests for community moderation
icon_url: data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwYXRoIGQ9Ik00IDEydjdjMCAuNTUuNDUgMSAxIDFoMTRjLjU1IDAgMS0uNDUgMS0xdi03Ii8+PHBhdGggZD0iTTEyIDE2VjMiLz48cGF0aCBkPSJNOCA3bDQtNCA0IDQiLz48L3N2Zz4=
"""

import json
import os
import re
import secrets
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict

from pydantic import BaseModel, Field


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

You can send specific chats to a public repository to share your good, bad, or interesting chats and help build better public AI. These chats can be used by anyone, subject to the "AI preference signals" and "licenses" you attach to the chats.

By default, your chats are not used directly for R&D. We may compute de‑identified aggregate stats (for example, total message volume) to operate the service.

You can always delete chats at any time or use temporary mode to ensure chats are not stored or used for any purpose.

How to setup public sharing:
1) Controls (top right) → Valves → Functions → Sharing
2) Toggle "Public Sharing Available" ON (Green)
3) Choose an Attribution Mode (anonymous, an automatically generated pseudonym like "publicai-fan-123", or, for power users, manually submit via your own Hugging Face account)
4) Choose a license.
5) Optional: Choose AI Preference (CC Signals) from the dropdown. Default is Ecosystem reciprocity (requires credit and invests back in shared tools). See CC Signals (https://creativecommons.org/ai/cc-signals/), RSL (https://rslstandard.org/), and our FAQ ({faq_url}). RSL integration is coming.
6) Close Chat Controls once you're done, and then click the "Sharing" button under your chat again!

Data FAQ: {faq_url} • Privacy Policy: {privacy_policy_url}

"""

# Visible warning block (ALWAYS VISIBLE)
PUBLIC_DATA_WARNING = (
    "**⚠️ You are about to share a chat publicly.**"
)

# Summarized header shown above details
PREVIEW_HEADER = (
    "**Assessment**: **{reason}** (`{sharing_tag}`); **Messages in your chat**: {num_messages}; "
    "**AI Preference Selected**: {ai_preference};  **How you show up**: {attribution}"
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

NER_PLACEHOLDER_BLOCK = """
<details>
<summary>Entity Flags (placeholder)</summary>
{ner_note}
</details>
"""

PREVIEW_TEMPLATE = """

# Ready to Share: "{title}"

{public_data_warning}

{tip_line}

Data FAQ: {faq_url} • Privacy Policy: {privacy_policy_url}

Privacy: {privacy_status}{privacy_note}


<details>
<summary>Details</summary>

{preview_header}


{privacy_block}

{grabbed_section}

</details>

{share_json_block}
{ner_block}

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
- License: {license}
- AI Preference: {ai_preference}
- Contributor Display: {attribution}
"""

PR_CREATED_RESULT = """
# Contribution sent! Thank you!

**Contribution #{pr_number}**: [View on HuggingFace]({pr_url})
**Status**: Awaiting review

**Contribution Summary**
- ID: `{contrib_id}`
- Assessment: {sharing_reason}
- Messages: {num_messages}
- License: {license}
- AI Preference: {ai_preference}
- Contributor Display: {attribution}
"""

PR_DESCRIPTION_TEMPLATE = """## Contribution Details

**Assessment**: {sharing_reason} (`{sharing_tag}`)
**Messages**: {num_messages}
**Attribution (declared)**: {attribution}

**License**: {license}
**AI Preference**: {ai_preference}
**Content Hash**: `{content_hash}`
**Submitted**: {submitted_at}

**Attribution Mode**: {attribution_mode}
**Verification**: {verification_json}
**Tags**: {tags_preview}

Submitted via the Flywheel OpenWebUI plugin.
"""

TIP_LINE = (
    "**Tip:** Update **tags** and **feedback** in the UI to add more detail to your contribution. "
    "We’ll auto‑grab the latest tags/feedback right before sending.\n"
)


# privacy_patterns.py
PRIVACY_PATTERNS = {
    # Phone numbers - more precise matching
    # International: enforce overall length 8–14 digits (excluding '+'), tolerate separators
    "phone_intl": (
        r"(?<!\d)\+(?:"
        r"(?:[1-9])(?:[-.\s]?\d){7,13}"  # 1-digit country code
        r"|(?:[1-9]\d)(?:[-.\s]?\d){6,12}"  # 2-digit country code
        r"|(?:[1-9]\d{2})(?:[-.\s]?\d){5,11}"  # 3-digit country code
        r")(?!\d)"
    ),
    "phone_us": r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
    # US digits only (no separators). Accept any NXX (0–9) but enforce [2-9] for area code.
    "phone_us_no_sep": r"(?<!\d)(?:\+?1)?(?:[2-9]\d{2}\d{7})(?!\d)",
    
    # Email - robust local and domain rules; disallow leading/trailing dot and consecutive dots in local part
    # Also ensure we don't match when preceded/followed by local-part chars (avoid '.startswithdot@...')
    "email": (
        r"(?<![A-Za-z0-9._%+-])"  # hard boundary before
        r"[A-Za-z0-9](?:[A-Za-z0-9_%+\-]*[A-Za-z0-9])?"  # local atom without leading/trailing dot
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9_%+\-]*[A-Za-z0-9])?)*"  # dot-separated atoms; no consecutive dots
        r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"  # domain labels; no leading/trailing hyphen
        r"(?![A-Za-z0-9._%+-])"  # hard boundary after
    ),
    
    # SSN - with format variations and invalid range exclusion
    "ssn": r"(?<!\d)(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}(?!\d)",
    
    # IP Address - IPv4 with better boundary detection; prevent matching inside longer dotted sequences
    "ip_address": r"(?<!\d)(?<!\.)(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?!\.\d)(?!\d)",
    
    # IPv6 Address - supports full and compressed forms (excludes IPv4-mapped)
    "ipv6_address": (
        r"(?<![A-Za-z0-9:])("  # hard boundary before (not hex/colon)
        r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:"
        r"|:(?::[A-Fa-f0-9]{1,4}){1,7}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}"
        r"|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}"
        r")(?!(?:[A-Za-z0-9:.]))"  # hard boundary after; don't allow '.' to avoid IPv4-mapped
    ),
    
    # AWS Keys - force case-sensitive even with IGNORECASE in tests; accept 20 or 21 total length for 'ASIA' variants
    "aws_access_key": r"\b(?-i:(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16,17})\b",
    "aws_secret_key": r"\b[A-Za-z0-9/+=]{40}\b",
    
    # Private Keys - multiple formats
    "private_key": r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----",
    
    # API Keys - common patterns with better specificity
    "api_key_stripe": r"\b(?:sk|pk)_(?:test_|live_)?[A-Za-z0-9]{24,}\b",
    "api_key_generic": r"\b(?:api[-_]?key|apikey|access[-_]?token)[-_:\s]*[A-Za-z0-9+/]{32,}\b",
    
    # Street Address - expanded street types
    "street_address": r"\b\d{1,5}\s+(?:[NSEW]\.?\s+)?[A-Za-z0-9\s\-\.]{2,30}\s+(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr(?:ive)?|Ct|Court|Cir(?:cle)?|Pl(?:aza)?|Way|Pkwy|Parkway|Pike|Ter(?:race)?|Trail|Path|Loop|Run|Pass|Cross(?:ing)?|Sq(?:uare)?)\b",
    
    # Credit Card - with Luhn validation support (checked in code/tests)
    "credit_card": r"\b(?:\d[-\s]?){13,19}\b",
    
    # Bank Account/Routing Numbers
    "routing_number": r"\b(?:ABA|Routing)[-:\s]*\d{9}\b",
    # IBAN: restrict to known IBAN country codes to avoid false positives (e.g., US)
    "iban": (
        r"\b(?:AL|AD|AT|AZ|BH|BE|BA|BR|BG|CR|HR|CY|CZ|DK|DO|EE|FO|FI|FR|GE|DE|GI|GR|GL|GT|HU|IS|IE|IL|IT|JO|KZ|KW|LV|LB|LI|LT|LU|MT|MR|MU|MC|MD|ME|NL|NO|PK|PS|PL|PT|QA|RO|SM|SA|RS|SK|SI|ES|SE|CH|TN|TR|AE|GB|VG|XK)\d{2}[A-Z0-9]{4,30}\b"
    ),
    
    # Government IDs - more specific patterns
    "us_passport": r"\b(?:[0-9]{9}|[A-Z][0-9]{8})\b",
    "ein": r"\b\d{2}-\d{7}\b",
    "medicare": r"\b[A-Z0-9]{4}-[A-Z0-9]{3}-[A-Z0-9]{4}\b",
    
    # Crypto addresses
    "bitcoin_address": r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b",
    "ethereum_address": r"\b0x[a-fA-F0-9]{40}\b",
}


# CC Preference Signal definitions used for human‑readable preview
AI_PREFERENCE_DEFS: Dict[str, str] = {
    "train-genai=n": "Deny training.",
    "train-genai=n;exceptions=cc-cr": "Allow training with Credit (attribution).",
    "train-genai=n;exceptions=cc-cr-dc": "Allow with Credit + Direct Contribution reciprocity.",
    "train-genai=n;exceptions=cc-cr-ec": "Allow with Credit + Ecosystem reciprocity.",
    "train-genai=n;exceptions=cc-cr-op": "Allow with Credit + Open reciprocity.",
    "ai-use=n": "Deny AI use.",
    "ai-use=n;exceptions=cc-cr": "Allow AI use with Credit (attribution).",
    "ai-use=n;exceptions=cc-cr-dc": "Allow with Credit + Direct Contribution reciprocity.",
    "ai-use=n;exceptions=cc-cr-ec": "Allow with Credit + Ecosystem reciprocity.",
    "ai-use=n;exceptions=cc-cr-op": "Allow with Credit + Open reciprocity.",
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
    license: Literal["CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"]
    # IETF Content-Usage expression (preset), e.g.,
    # "train-genai=n" or "train-genai=n;exceptions=cc-cr"
    ai_preference: str
    attribution: str
    attribution_mode: Literal["anonymous", "pseudonym", "manual_hf"]
    verification: Dict[str, Any]
    ai_preference_note: str
    ai_preference_time: str
    contributed_at: str
    content_hash: str
    version: str
    feedback_counts: Dict[str, int]
    # Map of clean_content message index (stringified) -> "good" | "bad"
    response_labels: Dict[str, Literal["good", "bad"]]


def validate_contribution(c: Dict[str, Any]) -> Contribution:
    required_keys = {
        "id",
        "title",
        "clean_content",
        "sharing_reason",
        "sharing_tag",
        "all_tags",
        "license",
        "ai_preference",
        "attribution",
        "attribution_mode",
        "verification",
        "ai_preference_note",
        "ai_preference_time",
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
    if c["attribution_mode"] not in ("anonymous", "pseudonym", "manual_hf"):
        raise ValueError("attribution_mode invalid")
    if c["license"] not in ("CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"):
        raise ValueError("license invalid")
    if not isinstance(c["ai_preference"], str) or not c["ai_preference"].strip():
        raise ValueError("ai_preference must be a non-empty string (Content-Usage expression)")
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
        debug_mode: bool = Field(
            default=True, description="Print debug diagnostics to console"
        )
        sanity_check_repo: bool = Field(
            default=True, description="Preflight: verify repo exists and token perms"
        )
        faq_url: str = Field(
            default="https://example.com/flywheel-faq", description="Data FAQ"
        )
        privacy_policy_url: str = Field(
            default="https://example.com/privacy", description="Privacy Policy"
        )
        min_messages: int = Field(
            default=2, description="Minimum messages required to share"
        )
        max_messages: int = Field(
            default=100, description="Maximum messages allowed per share (lowered)"
        )
        enable_ner_check: bool = Field(
            default=False, description="(Placeholder) NER check in preview"
        )

    class UserValves(BaseModel):
        public_sharing_available: bool = Field(
            default=False, description="Enable public sharing workflow"
        )

        # Attribution: simplified
        attribution_mode: Literal["anonymous", "pseudonym", "manual_hf"] = Field(
            default="anonymous",
            description=(
                "How your name appears on public contributions: "
                "anonymous = least linkability; "
                "pseudonym = deterministic (unsalted) handle from your account id (stable across contributions); "
                "manual_hf = you submit from your own Hugging Face account."
            ),
        )

        license: Literal["CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"] = Field(
            default="CC0-1.0",
            description=(
                "License for public contributions: "
                "CC0-1.0 = public domain dedication; "
                "CC-BY-4.0 = attribution required; "
                "CC-BY-SA-4.0 = attribution + share-alike."
            ),
        )
        # CC Preference Signals (dropdown). Integration with RSL is coming; see links below.
        # Training-focused options:
        # - "train-genai=n": Deny training.
        # - "train-genai=n;exceptions=cc-cr": Deny unless Credit (attribution) is provided.
        # - "train-genai=n;exceptions=cc-cr-dc": Deny unless Credit + Direct Contribution reciprocity.
        # - "train-genai=n;exceptions=cc-cr-ec": Deny unless Credit + Ecosystem reciprocity.
        # - "train-genai=n;exceptions=cc-cr-op": Deny unless Credit + Open reciprocity.
        # General AI-use options:
        # - "ai-use=n": Deny AI use.
        # - "ai-use=n;exceptions=cc-cr[ -dc | -ec | -op ]": Deny AI use unless the listed CC Signals reciprocity terms are met.
        # Reference: CC Signals https://creativecommons.org/ai/cc-signals/ • RSL https://rslstandard.org/ (integration coming)
        ai_preference: Literal[
            "train-genai=n",
            "train-genai=n;exceptions=cc-cr",
            "train-genai=n;exceptions=cc-cr-dc",
            "train-genai=n;exceptions=cc-cr-ec",
            "train-genai=n;exceptions=cc-cr-op",
            "ai-use=n",
            "ai-use=n;exceptions=cc-cr",
            "ai-use=n;exceptions=cc-cr-dc",
            "ai-use=n;exceptions=cc-cr-ec",
            "ai-use=n;exceptions=cc-cr-op",
        ] = Field(
            default="train-genai=n;exceptions=cc-cr-ec",
            description=(
                "AI Preference (CC Signals): choose a training‑focused option (train-genai=…) or a general AI‑use option (ai-use=…).\n"
                "Definitions — train-genai=n: deny training; +exceptions=cc-cr: allow with Credit (attribution); +cc-cr-dc: Credit + Direct Contribution reciprocity; +cc-cr-ec: Credit + Ecosystem reciprocity; +cc-cr-op: Credit + Open reciprocity.\n"
                "Default is Ecosystem reciprocity (…;cc-cr-ec) because it encourages attribution and contributions that benefit the broader community and tooling ecosystem.\n"
                "Learn more: CC Signals https://creativecommons.org/ai/cc-signals/ • RSL https://rslstandard.org/ • Our FAQ (see link in setup)."
            ),
        )
        # Note: Private researcher access is not available in the initial launch.

    def __init__(self):
        self.valves = self.Valves()
        self.user_valves = self.UserValves()
        self.db_path = str(Path.home() / ".open-webui" / "webui.db")
        self.recent_submissions: Dict[str, Tuple[datetime, str]] = (
            {}
        )  # chat_id -> (timestamp, pr_number)

    # ------------------------------------------------------------------
    # Debug
    # ------------------------------------------------------------------
    def _debug(self, *args):
        if self.valves.debug_mode:
            print("[Flywheel:DEBUG]", *args)

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
                pr_url = f"https://huggingface.co/datasets/{self.valves.dataset_repo}/discussions/{pr_number}"
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

    # Placeholder NER
    def _ner_placeholder(self) -> Dict[str, Any]:
        return {
            "enabled": False,
            "note": "NER placeholder; community extension welcome.",
        }

    def _ai_pref_definition(self, pref: str) -> str:
        try:
            return AI_PREFERENCE_DEFS.get(pref, "")
        except Exception:
            return ""

    # DB helpers (single-path queries)
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
        if mode == "manual_hf":
            return "Manual HF (Power User)", {
                "type": "hf",
                "status": "manual_pr_required",
            }
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
            # except HfHubHTTPError as he:
            #     sc = getattr(he.response, "status_code", None)
            #     out["ok"] = False
            #     out["errors"].append(f"repo_info failed (HTTP {sc})")
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
                license=contribution["license"],
                ai_preference=contribution.get("ai_preference", "Credit"),
                content_hash=contribution.get("content_hash", "N/A"),
                submitted_at=contribution["contributed_at"],
                attribution_mode=contribution.get("attribution_mode", "anonymous"),
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
                "https://huggingface.co/datasets/{}/discussions/{}".format(
                    dataset_repo, pr_num
                )
                if pr_num
                else getattr(commit_info, "pr_url", "Check repository")
            )
            return {"success": True, "pr_number": pr_num, "pr_url": pr_url}
        # except HfHubHTTPError as he:
        #     sc = getattr(he.response, "status_code", None)
        #     return {"success": False, "error": "HfHubHTTPError {}: {}".format(sc, he)}
        except Exception as e:
            return {"success": False, "error": "{}: {}".format(type(e).__name__, e)}

    # Message cleaning (preserve model/tool_calls and id if present)
    def _clean_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a simplified message list.

        Behavior:
        - Only the last message is scanned for known template headings (TRIM_MARKERS).
        - If found, keep content strictly before the first heading; drop the rest.
        - If nothing remains after trimming, drop the last message entirely.

        Transparency: We intentionally avoid complicated heuristics here to make
        behavior easy to reason about. This reduces accidental removal of normal
        chat content and keeps the flow predictable.

        Note: We preserve common fields (`id`, `model`, `tool_calls`) but do not
        reconstruct tool call flows yet. See README for planned improvements.
        """
        clean: List[Dict[str, Any]] = []

        def _trim_last_message_content(content: str) -> str:
            if not isinstance(content, str):
                return content
            # Find the first occurrence of any marker and slice content before it
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
                    # If nothing remains after trimming, drop the last message entirely
                    continue
            cm = {"role": msg["role"], "content": content}
            # Preserve a few common fields for continuity (advanced handling later)
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
        """Detect whether we are on the first run (build preview) or
        confirmation step (submit).

        Looks back up to WORKFLOW_SCAN_DEPTH messages for the JSON preview
        sentinels we render in the first run preview.
        """
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
        """Extract the JSON payload between the preview sentinels.

        Returns None if not found or if parsing fails.
        """
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

                # NER placeholder
                ner_result = self._ner_placeholder()

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
                        "license": user_valves.license,
                        "ai_preference": user_valves.ai_preference,
                        "attribution": attribution,
                        "attribution_mode": user_valves.attribution_mode,
                        "verification": verification,
                        "ai_preference_note": "Signal only; does not override explicit publication.",
                        "ai_preference_time": datetime.now(timezone.utc).isoformat(),
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

                # Mock-vs-Real: implicit based on creds presence (manual_hf forces mock/manual)
                have_hf_creds = bool(
                    self.valves.default_hf_token and self.valves.dataset_repo
                )
                manual_mode = user_valves.attribution_mode == "manual_hf"
                next_verb = (
                    "simulate" if (manual_mode or not have_hf_creds) else "create"
                )

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
                ner_block = (
                    NER_PLACEHOLDER_BLOCK.format(ner_note=ner_result.get("note", ""))
                    if ner_result.get("enabled")
                    else ""
                )

                # Human-readable definition appended to selected preference
                _pref_def = self._ai_pref_definition(user_valves.ai_preference)
                _pref_display = (
                    f"{user_valves.ai_preference} — {_pref_def}" if _pref_def else user_valves.ai_preference
                )

                preview_md = PREVIEW_TEMPLATE.format(
                    title=chat["title"],
                    public_data_warning=self._public_data_warning(user_valves),
                    preview_header=PREVIEW_HEADER.format(
                        reason=reason,
                        sharing_tag=sharing_tag,
                        num_messages=len(clean_messages),
                        ai_preference=_pref_display,
                        attribution=attribution,
                    ),
                    privacy_status=privacy_status,
                    privacy_note=privacy_note,
                    grabbed_section=grabbed_section,
                    tip_line=TIP_LINE,
                    faq_url=self.valves.faq_url,
                    privacy_policy_url=self.valves.privacy_policy_url,
                    share_json_block=share_json_block,
                    privacy_block=privacy_block,
                    ner_block=ner_block,
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
                        "license": user_valves.license,
                        "ai_preference": user_valves.ai_preference,
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
                hf_token = self.valves.default_hf_token
                have_hf_creds = bool(hf_token and self.valves.dataset_repo)
                manual_mode = user_valves.attribution_mode == "manual_hf"

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
                    mock_pr_url = (
                        "https://huggingface.co/datasets/{}/discussions/{}".format(
                            self.valves.dataset_repo, mock_pr_number
                        )
                    )
                    result = TEST_MODE_RESULT.format(
                        mock_pr_number=mock_pr_number,
                        dataset_repo=self.valves.dataset_repo,
                        mock_pr_url=mock_pr_url,
                        contrib_id=contribution["id"],
                        sharing_reason=contribution["sharing_reason"],
                        num_messages=len(contribution["clean_content"]),
                        license=contribution["license"],
                        ai_preference=contribution.get("ai_preference", "Credit"),
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

                    pr_result = self._create_pull_request(
                        self._sanitize_contribution_for_export(contribution),
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
                            license=contribution["license"],
                            ai_preference=contribution.get("ai_preference", "Credit"),
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
