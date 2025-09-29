"""
title: Share Chat Publicly (Trigger)
author: Public AI
version: 0.1
required_open_webui_version: 0.5.0
description: Quick trigger for the Flywheel Share tool with a short FAQ and confirmation.
icon_url: data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiIgc3Rya2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTggMTNsNC00IDQgNE02IDE5VjVhMiAyIDAgMCAxIDItMmg4YTIgMiAwIDAgMSAyIDJ2MTAiLz48L3N2Zz4=
"""

import json
from typing import Any, Dict

from pathlib import Path


class Action:
    def __init__(self):
        self.faq_url = "https://example.com/flywheel-faq"
        self.privacy_url = "https://example.com/privacy"

    async def action(self, body: dict, __user__=None, __event_emitter__=None, __event_call__=None, __metadata__=None):
        """
        Shows a quick FAQ and prompts to run the Share tool in one step.
        Works best with Function Calling = "default".
        """
        try:
            # Short FAQ popup
            faq_text = (
                f"You can share this chat publicly to help improve public AI.\n\n"
                f"- Privacy: We scan for obvious personal data, but please review the preview carefully.\n"
                f"- Licensing Intent: Choose your preferred high-level intent; we attach it to your contribution.\n"
                f"- Attribution: Anonymous, Pseudonym, or your Hugging Face account.\n\n"
                f"FAQ: {self.faq_url} • Privacy: {self.privacy_url}"
            )

            # Show a popup (confirmation modal). We don't wait for a response for maximum compatibility.
            await __event_emitter__({
                "type": "confirmation",
                "data": {
                    "message": faq_text + "\n\nUse the suggestions below to open the Share tool.",
                    "confirm_text": "OK",
                    "cancel_text": "Close"
                },
            })

            # Provide explicit follow-up to help the model trigger the tool
            await __event_emitter__({
                "type": "chat:message:follow_ups",
                "data": {"follow_ups": [
                    "Share this chat publicly", 
                    "Submit this chat publicly now"
                ]}
            })

            # Status note
            await __event_emitter__({
                "type": "status",
                "data": {"description": "Use a suggestion or Tools → Share to Flywheel", "done": True}
            })

        except Exception as e:
            await __event_emitter__({
                "type": "notification",
                "data": {"type": "error", "content": f"Error: {type(e).__name__}: {e}"},
            })
        return {"status": "complete"}
