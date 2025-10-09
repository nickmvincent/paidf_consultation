"""
title: Share to Flywheel (Tool)
author: Nicholas Vincent
version: 0.5
required_open_webui_version: 0.5.0
description: Share conversations via Pull Requests for community moderation (Tool variant)
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .flywheel_shared import (
    DEFAULT_FAQ_URL,
    DEFAULT_PRIVACY_POLICY_URL,
    DATALICENSES_URL,
    HUGGINGFACE_TOKENS_DOC_URL,
    HUGGINGFACE_TOKENS_SETTINGS_URL,
    HUGGINGFACE_DATASET_DISCUSSION_URL,
    PUBLICAI_GITHUB_URL,
    PUBLIC_DATA_WARNING,
    TIP_LINE,
    PREVIEW_HEADER,
    PREVIEW_TEMPLATE,
    TEST_MODE_RESULT,
    PR_CREATED_RESULT,
    SETUP_TEMPLATE,
    build_grabbed_section,
    build_privacy_block,
    build_share_json_block,
    validate_contribution,
    Contribution,
    compute_sharing_reason,
    resolve_attribution,
    hf_preflight,
    create_pull_request,
    clean_messages,
    detect_workflow_stage,
    extract_json_from_preview,
    map_response_labels,
    norm_tags,
    hash_messages,
    check_privacy,
    get_db_path,
    get_full_chat_data,
    now_iso,
)


class Tools:
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
        attribution_mode: str = Field(
            default="anonymous",
            description=(
                "How your name appears: anonymous | pseudonym | huggingface (token)."
            ),
        )
        license_intent: str = Field(
            default="AI devs who contribute back to the ecosystem",
            description=(
                "High‑level intent for data use. We will translate into enforceable terms as standards mature."
            ),
        )
        license_intent_note: str = Field(
            default="",
            description="Optional note to clarify your licensing intent.",
        )
        ai_thoughts: str = Field(
            default="", description="Optional: Your open‑ended thoughts about AI."
        )
        hf_user_token: str = Field(
            default="",
            description=(
                f"Your Hugging Face write token. Create/manage at {HUGGINGFACE_TOKENS_DOC_URL}"
            ),
        )

    def __init__(self):
        self.valves = self.Valves()
        self.db_path = get_db_path()

    # Exposed tool function
    def share_to_flywheel(
        self,
        confirm: bool = Field(
            default=False,
            description=(
                "Set True to submit; otherwise returns a preview."
            ),
        ),
        __chat_id__: Optional[str] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
        __user__: Dict[str, Any] = {},
        __event_emitter__=None,
        __request__=None,
    ) -> str:
        """
        Share current chat to Flywheel (Hugging Face dataset PR).
        First call returns a preview; call again (confirm=True) to submit.
        """

        user_valves = (__user__ or {}).get("valves")
        if not user_valves or not user_valves.public_sharing_available:
            return SETUP_TEMPLATE.format(
                faq_url=self.valves.faq_url,
                privacy_policy_url=self.valves.privacy_policy_url,
                hf_tokens_doc_url=HUGGINGFACE_TOKENS_DOC_URL,
                hf_tokens_settings_url=HUGGINGFACE_TOKENS_SETTINGS_URL,
                datalicenses_url=DATALICENSES_URL,
            )

        if not __chat_id__:
            return "Error: No chat selected."

        stage = "confirm_run" if confirm else "first_run"
        if not confirm and __messages__:
            stage, preview_content = detect_workflow_stage(__messages__)
        else:
            preview_content = None

        # FIRST RUN → Build preview
        if stage == "first_run":
            chat = get_full_chat_data(self.db_path, __chat_id__, request=__request__, user=__user__)
            clean = clean_messages(chat["messages"])

            if len(clean) < self.valves.min_messages:
                return f"Too short. Minimum {self.valves.min_messages} messages required."
            if len(clean) > self.valves.max_messages:
                return f"Too long. Maximum {self.valves.max_messages}. Consider splitting."

            privacy = check_privacy(clean)
            privacy_status = (
                "✅ No obvious personal data detected"
                if not privacy.get("has_issues")
                else "⚠️ Possible personal data present"
            )
            privacy_note = (
                " — please review the content carefully before sharing."
                if privacy.get("has_issues")
                else ""
            )

            norm = norm_tags(chat["tags"])
            sharing_tag, reason = compute_sharing_reason(chat["feedback_counts"])

            attribution, verification = resolve_attribution(
                user_valves.attribution_mode, __user__
            )

            # sample feedback transparency
            sample_feedback = []
            for it in chat["feedback_items"][:5]:
                data = it.get("data") or {}
                meta = it.get("meta") or {}
                sample_feedback.append(
                    {
                        "id": it.get("id"),
                        "type": it.get("type"),
                        "rating": data.get("rating"),
                        "model_id": data.get("model_id") or meta.get("model_id"),
                        "chat_id": meta.get("chat_id"),
                        "created_at": it.get("created_at"),
                        "tags": (data.get("tags") if isinstance(data.get("tags"), list) else None),
                    }
                )
            sample_feedback_json = json.dumps(sample_feedback, indent=2, ensure_ascii=False)

            contrib_id = f"contrib_{secrets.token_urlsafe(8)}"
            messages_hash = hash_messages(clean)
            response_labels = map_response_labels(chat["messages"], clean, chat["feedback_items"])

            contribution: Contribution = validate_contribution(
                {
                    "id": contrib_id,
                    "title": chat["title"],
                    "clean_content": clean,
                    "sharing_reason": reason,
                    "sharing_tag": sharing_tag,
                    "all_tags": norm,
                    "license_intent": user_valves.license_intent,
                    "license_intent_note": user_valves.license_intent_note,
                    "ai_thoughts": user_valves.ai_thoughts,
                    "attribution": attribution,
                    "attribution_mode": user_valves.attribution_mode,
                    "verification": verification,
                    "contributed_at": now_iso(),
                    "content_hash": messages_hash,
                    "version": "1.0.0",
                    "feedback_counts": chat["feedback_counts"],
                    "response_labels": response_labels,
                }
            )

            export_contribution = contribution.copy()
            share_json_block = build_share_json_block(export_contribution)
            privacy_block = build_privacy_block(privacy)
            grabbed_section = build_grabbed_section(
                norm, chat["feedback_counts"], sample_feedback_json, reason
            )

            use_user_token = (
                user_valves.attribution_mode == "huggingface"
                and (user_valves.hf_user_token or "").strip()
            )
            have_app_token = bool(self.valves.default_hf_token and self.valves.dataset_repo)
            submit_via = (
                "your Hugging Face account" if use_user_token else (
                    "app account" if have_app_token else "simulation"
                )
            )
            next_verb = ("create" if (use_user_token or have_app_token) else "simulate")

            preview_md = PREVIEW_TEMPLATE.format(
                title=chat["title"],
                public_data_warning=PUBLIC_DATA_WARNING,
                preview_header=PREVIEW_HEADER.format(
                    reason=reason,
                    sharing_tag=sharing_tag,
                    num_messages=len(clean),
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
                    "- Contributor Thoughts (AI): {}\n".format(user_valves.ai_thoughts.strip())
                    if (user_valves.ai_thoughts or "").strip() else ""
                ),
                intent_note_block=(
                    (
                        "Note on Licensing Intents and AI Thoughts\n\n"
                        "We capture your natural‑language licensing intent and any optional thoughts on AI. As standards mature, we will translate these into concrete licenses and/or AI‑use preference signals. For now, there is no firm legal contract: submissions are published publicly on Hugging Face with a lightweight contributor agreement and may be mirrored later on a static site with anti‑scraping. As the Public AI movement grows, we’ll formalize this. Iterating on licenses and signals is a great way to contribute — join us on GitHub: {}"
                    ).format(PUBLICAI_GITHUB_URL)
                ),
                next_verb=next_verb,
            )
            return preview_md

        # CONFIRM RUN → re-compare and (mock|real) PR
        else:
            if not preview_content and __messages__:
                # try to get from recent content
                for msg in reversed(__messages__[-10:]):
                    pc = extract_json_from_preview(msg.get("content") or "")
                    if pc:
                        preview_content = msg.get("content")
                        break

            if not preview_content:
                return "Error: Could not read preview data. Try again."

            contribution = extract_json_from_preview(preview_content) or {}
            try:
                contribution = validate_contribution(contribution)  # type: ignore
            except Exception as e:
                return f"Preview invalid: {e}"

            chat = get_full_chat_data(self.db_path, __chat_id__, request=__request__, user=__user__)
            fresh_messages = clean_messages(chat["messages"])
            fresh_hash = hash_messages(fresh_messages)
            new_sharing_tag, new_reason = compute_sharing_reason(chat["feedback_counts"])

            preview_tags = norm_tags(contribution.get("all_tags", []))
            fresh_tags = norm_tags(chat["tags"])
            preview_feedback = {
                "good": int(contribution.get("feedback_counts", {}).get("good", 0)),
                "bad": int(contribution.get("feedback_counts", {}).get("bad", 0)),
            }
            fresh_feedback = {
                "good": int(chat["feedback_counts"].get("good", 0)),
                "bad": int(chat["feedback_counts"].get("bad", 0)),
            }

            changed = (preview_tags != fresh_tags) or (preview_feedback != fresh_feedback)

            attribution, verification = resolve_attribution(
                user_valves.attribution_mode, __user__
            )
            contribution.update(
                {
                    "clean_content": fresh_messages,
                    "content_hash": fresh_hash,
                    "all_tags": fresh_tags,
                    "feedback_counts": fresh_feedback,
                    "response_labels": map_response_labels(
                        chat["messages"], fresh_messages, chat["feedback_items"]
                    ),
                    "sharing_tag": new_sharing_tag,
                    "sharing_reason": new_reason,
                    "attribution": attribution,
                    "verification": verification,
                    "license_intent": user_valves.license_intent,
                    "license_intent_note": user_valves.license_intent_note,
                    "ai_thoughts": user_valves.ai_thoughts,
                    "contributed_at": now_iso(),
                }
            )
            try:
                contribution = validate_contribution(contribution)  # type: ignore
            except Exception as e:
                return f"Updated data invalid: {e}"

            use_user_token = (
                user_valves.attribution_mode == "huggingface"
                and (user_valves.hf_user_token or "").strip()
            )
            hf_token = (
                user_valves.hf_user_token
                if use_user_token
                else self.valves.default_hf_token
            )
            have_hf_creds = bool(hf_token and self.valves.dataset_repo)
            manual_mode = (user_valves.attribution_mode == "huggingface" and not use_user_token)

            if have_hf_creds and not manual_mode and self.valves.sanity_check_repo:
                pf = hf_preflight(self.valves.dataset_repo, hf_token)
                if not pf.get("ok"):
                    lines = ["Preflight checks failed:"]
                    lines += [f"- {e}" for e in pf.get("errors", [])]
                    who = pf.get("who") or {}
                    if who:
                        lines.append(
                            f"- Token user: {who.get('name') or who.get('email') or who.get('orgs', [])}"
                        )
                    return "\n".join(lines)

            if (not have_hf_creds) or manual_mode:
                mock_pr_number = "MOCK-123"
                mock_pr_url = HUGGINGFACE_DATASET_DISCUSSION_URL.format(
                    repo=self.valves.dataset_repo, num=mock_pr_number
                )
                return TEST_MODE_RESULT.format(
                    mock_pr_number=mock_pr_number,
                    dataset_repo=self.valves.dataset_repo,
                    mock_pr_url=mock_pr_url,
                    contrib_id=contribution["id"],
                    sharing_reason=contribution["sharing_reason"],
                    num_messages=len(contribution["clean_content"]),
                    license_intent=contribution.get("license_intent", "unspecified"),
                    license_intent_note=contribution.get("license_intent_note", "—") or "—",
                    ai_thoughts=contribution.get("ai_thoughts", "—") or "—",
                    submit_via=(
                        "your Hugging Face account" if use_user_token else (
                            "app account" if self.valves.default_hf_token else "simulation"
                        )
                    ),
                    attribution=contribution.get("attribution", "anonymous"),
                )

            # real PR
            pr_result = create_pull_request(contribution, hf_token, self.valves.dataset_repo)
            if pr_result.get("success"):
                pr_url = pr_result["pr_url"]
                pr_number = pr_result.get("pr_number", "N/A")
                return PR_CREATED_RESULT.format(
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
                return f"PR creation failed: {pr_result.get('error', 'Unknown error')}"
