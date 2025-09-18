"""
title: Debug Chat Tags and Feedback
author: Public AI
version: 0.1
required_open_webui_version: 0.5.0
description: Inspect raw tag and feedback objects for the current chat
icon_url: data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiB2aWV3Qm94PSIwIDAgMjQgMjQiPjxwYXRoIGQ9Ik0xMC41IDE2LjVhNCA0IDAgMSAxIDAtOCA0IDQgMCAwIDEgMCA4em0wIDZBMTAgMTAgMCAxIDAgOSAxYTEwIDEwIDAgMCAwIDEuNSAxOS41WiIvPjwvc3ZnPg==
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


class Action:
    def __init__(self):
        # Default OpenWebUI DB path
        self.db_path = str(Path.home() / ".open-webui" / "webui.db")

    async def action(self, body: dict, __user__=None, __event_emitter__=None, __event_call__=None):
        chat_id = (body or {}).get("chat_id")
        if not chat_id:
            await __event_emitter__({
                "type": "notification",
                "data": {"type": "error", "content": "No chat selected"},
            })
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Chat row
            cur.execute("SELECT id, title, meta, chat, created_at, updated_at FROM chat WHERE id = ?", (chat_id,))
            chat_row = cur.fetchone()
            if not chat_row:
                await __event_emitter__({
                    "type": "notification",
                    "data": {"type": "error", "content": f"Chat not found: {chat_id}"},
                })
                return

            chat_dict: Dict[str, Any] = dict(chat_row)
            # Parse meta and chat payload if JSON strings
            for key in ("meta", "chat"):
                val = chat_dict.get(key)
                if isinstance(val, str):
                    try:
                        chat_dict[key] = json.loads(val)
                    except Exception:
                        pass

            # Tags from chatidtag
            cur.execute("SELECT tag_name FROM chatidtag WHERE chat_id = ?", (chat_id,))
            tag_rows = [dict(r) for r in cur.fetchall()]

            # Feedback rows possibly associated with this chat; show raw shapes
            # We’ll fetch a few by multiple candidate selectors to see what exists
            fb_candidates: List[Dict[str, Any]] = []
            queries = [
                ("meta.chat_id", "SELECT id, type, data, meta, created_at FROM feedback WHERE json_extract(meta, '$.chat_id') = ? ORDER BY created_at DESC LIMIT 15"),
                ("data.chat_id", "SELECT id, type, data, meta, created_at FROM feedback WHERE json_extract(data, '$.chat_id') = ? ORDER BY created_at DESC LIMIT 15"),
                ("meta.chatId", "SELECT id, type, data, meta, created_at FROM feedback WHERE json_extract(meta, '$.chatId') = ? ORDER BY created_at DESC LIMIT 15"),
                ("data.chatId", "SELECT id, type, data, meta, created_at FROM feedback WHERE json_extract(data, '$.chatId') = ? ORDER BY created_at DESC LIMIT 15"),
            ]
            for label, q in queries:
                cur.execute(q, (chat_id,))
                rows = cur.fetchall()
                parsed = []
                for r in rows:
                    d = dict(r)
                    # Preserve raw and parsed forms of data/meta
                    raw_data, raw_meta = d.get("data"), d.get("meta")
                    d["_raw_data"] = raw_data
                    d["_raw_meta"] = raw_meta
                    for k in ("data", "meta"):
                        val = d.get(k)
                        if isinstance(val, str):
                            try:
                                d[k] = json.loads(val)
                            except Exception:
                                pass
                    parsed.append(d)
                if parsed:
                    fb_candidates.append({"selector": label, "count": len(parsed), "items": parsed})

            # Compose compact debug output
            out = {
                "chat_id": chat_id,
                "chat_title": chat_dict.get("title"),
                "chat_meta_keys": list((chat_dict.get("meta") or {}).keys()) if isinstance(chat_dict.get("meta"), dict) else type(chat_dict.get("meta")).__name__,
                "chat_payload_keys": list((chat_dict.get("chat") or {}).keys()) if isinstance(chat_dict.get("chat"), dict) else type(chat_dict.get("chat")).__name__,
                "chat_payload_sample_messages": (chat_dict.get("chat") or {}).get("messages", [])[:2] if isinstance(chat_dict.get("chat"), dict) else [],
                "tags_table_rows": tag_rows,
                "meta_tags": (chat_dict.get("meta") or {}).get("tags") if isinstance(chat_dict.get("meta"), dict) else None,
                "chat_tags": (chat_dict.get("chat") or {}).get("tags") if isinstance(chat_dict.get("chat"), dict) else None,
                "feedback_candidates": fb_candidates,
            }

            md = (
                "# Debug: Chat Tags and Feedback\n\n"
                "Copy the JSON below so we can align the action to real shapes.\n\n"
                "~~~json\n" + json.dumps(out, indent=2, ensure_ascii=False) + "\n~~~\n"
            )
            await __event_emitter__({"type": "message", "data": {"content": md}})
            await __event_emitter__({"type": "status", "data": {"description": "Complete", "done": True}})

        except Exception as e:
            await __event_emitter__({
                "type": "notification",
                "data": {"type": "error", "content": f"Error: {e}"},
            })
        finally:
            try:
                conn.close()
            except Exception:
                pass

        return {"status": "complete"}

