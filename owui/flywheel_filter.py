"""
title: Share to Flywheel (Filter)
author: Nicholas Vincent
version: 0.5
required_open_webui_version: 0.5.0
description: Share conversations via Pull Requests for community moderation (Filter variant)
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


class Filter:
    class Valves(BaseModel):
        priority: int = Field(default=0, description="Filter priority")
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
        attribution_mode: str = Field(default="anonymous")
        license_intent: str = Field(
            default="AI devs who contribute back to the ecosystem"
        )
        license_intent_note: str = Field(default="")
        ai_thoughts: str = Field(default="")
        hf_user_token: str = Field(default="")

    def __init__(self):
        self.valves = self.Valves()
        self.db_path = get_db_path()

    def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __chat_id__: Optional[str] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
        __request__: Optional[object] = None,
    ) -> dict:
        # No-op at inlet; we render in outlet so the user sees a message immediately.
        return body

    def outlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __chat_id__: Optional[str] = None,
        __messages__: Optional[List[Dict[str, Any]]] = None,
        __request__: Optional[object] = None,
    ) -> dict:
        user_valves = (__user__ or {}).get("valves")
        if not user_valves or not user_valves.public_sharing_available:
            # Leave model response intact when sharing is not enabled
            return body

        if not __chat_id__:
            return body

        # Auto-share path: assess quality and submit immediately (no preview)
        chat = get_full_chat_data(self.db_path, __chat_id__, request=__request__, user=__user__)
        fresh_messages = clean_messages(chat["messages"])
        # Guardrails: basic size + privacy check
        if len(fresh_messages) < self.valves.min_messages or len(fresh_messages) > self.valves.max_messages:
            return body
        privacy = check_privacy(fresh_messages)
        if privacy.get("has_issues"):
            return {"messages": [{"role": "assistant", "content": "Sharing skipped due to possible personal data. Adjust content or privacy settings to allow automatic sharing."}]}

        fresh_hash = hash_messages(fresh_messages)
        fresh_tags = norm_tags(chat["tags"])
        new_sharing_tag, new_reason = compute_sharing_reason(chat["feedback_counts"])
        # Only share when clearly high or low quality; mixed is skipped
        if new_reason not in ("good", "bad"):
            return body

        attribution, verification = resolve_attribution(user_valves.attribution_mode, __user__ or {})
        response_labels = map_response_labels(chat["messages"], fresh_messages, chat["feedback_items"])
        contribution: Contribution = validate_contribution(
            {
                "id": f"contrib_{secrets.token_urlsafe(8)}",
                "title": chat["title"],
                "clean_content": fresh_messages,
                "sharing_reason": new_reason,
                "sharing_tag": new_sharing_tag,
                "all_tags": fresh_tags,
                "license_intent": user_valves.license_intent,
                "license_intent_note": user_valves.license_intent_note,
                "ai_thoughts": user_valves.ai_thoughts,
                "attribution": attribution,
                "attribution_mode": user_valves.attribution_mode,
                "verification": verification,
                "contributed_at": now_iso(),
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
        hf_token = user_valves.hf_user_token if use_user_token else self.valves.default_hf_token
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
                return {"messages": [{"role": "assistant", "content": "\n".join(lines)}]}

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
                submit_via=(
                    "your Hugging Face account" if use_user_token else (
                        "app account" if self.valves.default_hf_token else "simulation"
                    )
                ),
                attribution=contribution.get("attribution", "anonymous"),
            )
            return {"messages": [{"role": "assistant", "content": result}]}

        pr_result = create_pull_request(contribution, hf_token, self.valves.dataset_repo)
        if pr_result.get("success"):
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
            return {"messages": [{"role": "assistant", "content": result}]}
        else:
            detail = pr_result.get("error", "Unknown error")
            return {"messages": [{"role": "assistant", "content": f"PR creation failed: {detail}"}]}
