import asyncio
import json
import os
import sqlite3
import tempfile
import types
import sys
import unittest
from datetime import datetime

from flywheel import Action, validate_contribution


# ------------------------------
# Test utilities
# ------------------------------

def make_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE chat (id TEXT PRIMARY KEY, title TEXT, meta TEXT, chat TEXT, created_at TEXT, updated_at TEXT)"
    )
    cur.execute("CREATE TABLE chatidtag (chat_id TEXT, tag_name TEXT)")
    cur.execute(
        "CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, data TEXT, meta TEXT, created_at TEXT)"
    )
    conn.commit()
    return conn


async def run_action(action, chat_id, messages_stub, user, emitter_events):
    async def emitter(evt):
        emitter_events.append(evt)

    await action.action(
        {"chat_id": chat_id, "messages": messages_stub},
        __user__=user,
        __event_emitter__=emitter,
    )


async def run_action_twice(action, chat_id, messages_stub, user, emitter_events):
    await run_action(action, chat_id, messages_stub, user, emitter_events)
    await run_action(action, chat_id, messages_stub, user, emitter_events)


def event_types(events):
    return [e.get("type") for e in events]


def last_message_content(events):
    msgs = [e for e in events if e.get("type") == "message"]
    return (msgs[-1].get("data") or {}).get("content") if msgs else None


def messages_from_preview(preview_content):
    # Minimal chat stub containing the assistant preview so workflow moves to confirm_run
    return [
        {"role": "user", "content": "please share"},
        {"role": "assistant", "content": preview_content},
    ]


class FlywheelHelperTests(unittest.TestCase):
    def setUp(self):
        self.action = Action()

    def test_norm_tags(self):
        self.assertEqual(self.action._norm_tags([" A ", "a", "B", "b", None, ""]), ["a", "b"])  # type: ignore[list-item]

    def test_hash_messages_stability_and_sensitivity(self):
        msgs = [
            {"role": "user", "content": "hi", "model": "m1"},
            {"role": "assistant", "content": "hello", "tool_calls": [{"id": 1}]},
        ]
        h1 = self.action._hash_messages(msgs)
        h2 = self.action._hash_messages(msgs)
        self.assertEqual(h1, h2)

        msgs2 = [
            {"role": "user", "content": "hi", "model": "m2"},  # model differs
            {"role": "assistant", "content": "hello", "tool_calls": [{"id": 1}]},
        ]
        h3 = self.action._hash_messages(msgs2)
        self.assertNotEqual(h1, h3)

    def test_deterministic_pseudonym(self):
        u = {"id": "user-xyz"}
        p1 = self.action._deterministic_pseudonym(u)
        p2 = self.action._deterministic_pseudonym(u)
        self.assertEqual(p1, p2)
        self.assertNotEqual(p1, self.action._deterministic_pseudonym({"id": "other"}))

    def test_luhn(self):
        # Valid Visa test number (commonly used for testing)
        valid = "4111 1111 1111 1111"
        invalid = "4111 1111 1111 1112"
        self.assertTrue(self.action._luhn_ok(valid))
        self.assertFalse(self.action._luhn_ok(invalid))

    def test_check_privacy(self):
        msgs = [
            {"role": "user", "content": "email a@b.com and card 4111 1111 1111 1111"},
            {"role": "assistant", "content": "call me at +1 415-555-1234"},
        ]
        res = self.action._check_privacy(msgs)
        self.assertTrue(res["has_issues"])  # found items
        self.assertIn("email", res["types_found"])
        self.assertIn("credit_card", res["types_found"])  # luhn filters apply
        self.assertIn("phone_us", res["types_found"])  # E.164 US format

    def test_clean_messages(self):
        msgs = [
            {"role": "user", "content": "hi", "extra": "x"},
            {"role": "assistant", "content": "hello", "model": "m"},
            {"role": "tool", "content": "used", "tool_calls": [{"x": 1}]},
            "ignore-me",
        ]
        clean = self.action._clean_messages(msgs)  # type: ignore[arg-type]
        self.assertEqual(len(clean), 3)
        self.assertNotIn("extra", clean[0])
        self.assertIn("model", clean[1])
        self.assertIn("tool_calls", clean[2])

    def test_detect_workflow_and_extract(self):
        msgs = [
            {"role": "user", "content": "hello"},
        ]
        stage, content = self.action._detect_workflow_stage(msgs)
        self.assertEqual(stage, "first_run")
        self.assertIsNone(content)

        preview = """
        <<<SHARE_PREVIEW_START>>>
        {"id":"x"}
        <<<SHARE_PREVIEW_END>>>
        **Next Step**: Click the Share button again
        """
        msgs2 = [{"role": "assistant", "content": preview}]
        stage2, content2 = self.action._detect_workflow_stage(msgs2)
        self.assertEqual(stage2, "confirm_run")
        data = self.action._extract_json_from_preview(content2)
        self.assertEqual(data["id"], "x")

    def test_compute_sharing_reason(self):
        self.assertEqual(self.action._compute_sharing_reason({"good": 2, "bad": 1}), ("dataset-good", "good"))
        self.assertEqual(self.action._compute_sharing_reason({"good": 1, "bad": 2}), ("dataset-bad", "bad"))
        self.assertEqual(self.action._compute_sharing_reason({"good": 1, "bad": 1}), ("dataset-mixed", "mixed"))

    def test_resolve_attribution(self):
        uv = self.action.user_valves
        uv.attribution_mode = "anonymous"
        name, ver = self.action._resolve_attribution(uv, {"id": "u"})
        self.assertEqual(name, "Anonymous")
        uv.attribution_mode = "pseudonym"
        name2, ver2 = self.action._resolve_attribution(uv, {"id": "u"})
        self.assertNotEqual(name2, "Anonymous")
        uv.attribution_mode = "huggingface"
        name3, ver3 = self.action._resolve_attribution(uv, {"id": "u"})
        self.assertIn("Hugging Face", name3)

    def test_validate_contribution(self):
        base = {
            "id": "c",
            "title": "t",
            "clean_content": [{"role": "user", "content": "hi"}],
            "sharing_reason": "good",
            "sharing_tag": "dataset-good",
            "all_tags": [],
            "license_intent": "AI devs who contribute back to the ecosystem",
            "license_intent_note": "",
            "ai_thoughts": "some thoughts",
            "ai_preference": "train-genai=n",
            "attribution": "a",
            "attribution_mode": "anonymous",
            "verification": {},
            "ai_preference_note": "n",
            "ai_preference_time": "t",
            "contributed_at": "t",
            "content_hash": "h",
            "version": "1.0.0",
            "feedback_counts": {"good": 1, "bad": 0},
            "response_labels": {},
        }
        self.assertIsInstance(validate_contribution(dict(base)), dict)
        bad = dict(base)
        bad["sharing_reason"] = "meh"
        with self.assertRaises(ValueError):
            validate_contribution(bad)


class FlywheelActionFlowTests(unittest.TestCase):
    def setUp(self):
        # fresh temp DB and action per test
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "webui.db")
        conn = make_db(self.db_path)

        self.chat_id = "c1"
        self.chat_payload = {
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi there"},
            ]
        }
        conn.execute(
            "INSERT INTO chat (id, title, meta, chat, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                self.chat_id,
                "Sample Chat",
                json.dumps({}),
                json.dumps(self.chat_payload),
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.execute(
            "INSERT INTO chatidtag (chat_id, tag_name) VALUES (?, ?)",
            (self.chat_id, "demo"),
        )
        conn.execute(
            "INSERT INTO feedback (type, data, meta, created_at) VALUES (?, ?, ?, ?)",
            (
                "good",
                json.dumps({"rating": "+1"}),
                json.dumps({"chat_id": self.chat_id}),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        self.action = Action()
        self.action.db_path = self.db_path
        # Enable public sharing for tests
        self.action.user_valves.public_sharing_available = True
        self.user = {"valves": self.action.user_valves, "id": "user-123"}

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_entry_requires_opt_in(self):
        # Disable public sharing to trigger setup screen
        self.action.user_valves.public_sharing_available = False
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))
        self.assertIn("message", event_types(events))
        content = last_message_content(events)
        self.assertIn("Share Chat Publicly", content)

    def test_too_short_and_too_long(self):
        # Too short
        self.action.valves.min_messages = 3
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))
        notes = [e for e in events if e.get("type") == "notification"]
        self.assertTrue(any("Too short" in (n.get("data") or {}).get("content", "") for n in notes))

        # Too long
        self.action.valves.min_messages = 1
        self.action.valves.max_messages = 1
        events2 = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events2))
        notes2 = [e for e in events2 if e.get("type") == "notification"]
        self.assertTrue(any("Too long" in (n.get("data") or {}).get("content", "") for n in notes2))

    def test_first_run_preview_and_confirm_test_mode(self):
        # huggingface (without token) forces test mode
        self.action.user_valves.attribution_mode = "huggingface"
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))
        content = last_message_content(events)
        self.assertIn("<<<SHARE_PREVIEW_START>>>", content)
        self.assertIn("Next Step", content)

        # confirm run should simulate PR
        events2 = []
        confirm_msgs = messages_from_preview(content)
        asyncio.run(run_action(self.action, self.chat_id, confirm_msgs, self.user, events2))
        content2 = last_message_content(events2)
        self.assertIn("Test Mode: PR Preview", content2)

    def test_pseudonym_appears_in_preview(self):
        # Enable pseudonym mode and ensure preview attribution matches deterministic handle
        self.action.user_valves.attribution_mode = "pseudonym"
        user = {"valves": self.action.user_valves, "id": "user-pseudo-xyz"}
        expected = self.action._deterministic_pseudonym(user)

        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], user, events))
        content = last_message_content(events)
        self.assertIn("<<<SHARE_PREVIEW_START>>>", content)
        contrib = self.action._extract_json_from_preview(content)
        self.assertIsNotNone(contrib)
        self.assertEqual(contrib.get("attribution_mode"), "pseudonym")
        self.assertEqual(contrib.get("attribution"), expected)

    def test_feedback_association_filters_by_chat_id(self):
        # Build initial preview and capture counts
        self.action.user_valves.attribution_mode = "huggingface"
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))
        content1 = last_message_content(events)
        # Extract preview JSON to read feedback_counts
        data1 = self.action._extract_json_from_preview(content1)
        self.assertIsNotNone(data1)
        base_counts = (data1 or {}).get("feedback_counts", {})
        self.assertEqual(base_counts.get("good"), 1)
        self.assertEqual(base_counts.get("bad"), 0)

        # Add unrelated feedback linked to a different chat
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO feedback (type, data, meta, created_at) VALUES (?, ?, ?, ?)",
            (
                "good",
                json.dumps({"rating": "+1", "chat_id": "other"}),
                json.dumps({}),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit(); conn.close()

        # Build preview again; counts should remain unchanged for this chat
        events2 = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events2))
        content2 = last_message_content(events2)
        data2 = self.action._extract_json_from_preview(content2)
        self.assertIsNotNone(data2)
        counts2 = (data2 or {}).get("feedback_counts", {})
        self.assertEqual(counts2.get("good"), 1)
        self.assertEqual(counts2.get("bad"), 0)

    def test_confirm_grabs_latest_on_tag_change(self):
        self.action.user_valves.attribution_mode = "huggingface"
        # Build preview first
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))

        # Change tags
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO chatidtag (chat_id, tag_name) VALUES (?, ?)",
            (self.chat_id, "newtag"),
        )
        conn.commit(); conn.close()

        # Confirm run → refresh
        events2 = []
        confirm_msgs = messages_from_preview(last_message_content(events))
        asyncio.run(run_action(self.action, self.chat_id, confirm_msgs, self.user, events2))
        # Expect a toast and proceed to simulated PR
        notes = [e for e in events2 if e.get("type") == "notification"]
        self.assertTrue(any("Latest tags/feedback grabbed" in (n.get("data") or {}).get("content", "") for n in notes))
        content2 = last_message_content(events2)
        self.assertIn("Test Mode: PR Preview", content2)

    def test_confirm_grabs_latest_on_feedback_change(self):
        self.action.user_valves.attribution_mode = "huggingface"
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))

        # Add a bad feedback to flip counts
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO feedback (type, data, meta, created_at) VALUES (?, ?, ?, ?)",
            (
                "bad",
                json.dumps({"rating": "-1"}),
                json.dumps({"chat_id": self.chat_id}),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit(); conn.close()

        events2 = []
        confirm_msgs = messages_from_preview(last_message_content(events))
        asyncio.run(run_action(self.action, self.chat_id, confirm_msgs, self.user, events2))
        notes = [e for e in events2 if e.get("type") == "notification"]
        self.assertTrue(any("Latest tags/feedback grabbed" in (n.get("data") or {}).get("content", "") for n in notes))
        content2 = last_message_content(events2)
        self.assertIn("Test Mode: PR Preview", content2)

    def test_preflight_failure_blocks_real_pr(self):
        # Not manual; provide fake creds so preflight runs, but hf missing → preflight returns ok=False
        self.action.user_valves.attribution_mode = "anonymous"
        self.action.valves.default_hf_token = "hf_fake"
        self.action.valves.dataset_repo = "owner/repo"
        self.action.valves.sanity_check_repo = True

        # Build preview first
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))

        # Confirm run → should hit preflight fail and notify error
        events2 = []
        confirm_msgs = messages_from_preview(last_message_content(events))
        asyncio.run(run_action(self.action, self.chat_id, confirm_msgs, self.user, events2))
        notes = [e for e in events2 if e.get("type") == "notification"]
        self.assertTrue(any("Preflight checks failed" in (n.get("data") or {}).get("content", "") for n in notes))

    def test_real_pr_path_and_dedup_guard_with_mock(self):
        # Disable preflight to skip dependency, emulate installed hub module, and mock PR creation
        self.action.user_valves.attribution_mode = "anonymous"
        self.action.valves.default_hf_token = "hf_fake"
        self.action.valves.dataset_repo = "owner/repo"
        self.action.valves.sanity_check_repo = False

        # Stub huggingface_hub presence for import site
        dummy = types.ModuleType("huggingface_hub")
        class HfApi:  # minimal stub
            pass
        dummy.HfApi = HfApi
        sys.modules["huggingface_hub"] = dummy

        # Build preview first
        events = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events))

        # Mock the PR creation to succeed with a number
        def fake_create_pr(contribution, hf_token, dataset_repo):
            return {"success": True, "pr_number": 42, "pr_url": "https://example/pr/42"}

        self.action._create_pull_request = fake_create_pr  # type: ignore[assignment]

        # Confirm run → should post PR created message and record submission
        events2 = []
        confirm_msgs = messages_from_preview(last_message_content(events))
        asyncio.run(run_action(self.action, self.chat_id, confirm_msgs, self.user, events2))
        content2 = last_message_content(events2)
        self.assertIn("Contribution sent! Thank you!", content2)

        # Immediately try to build preview again (first_run path) → dedup guard should warn
        events3 = []
        asyncio.run(run_action(self.action, self.chat_id, [], self.user, events3))
        notes = [e for e in events3 if e.get("type") == "notification"]
        self.assertTrue(any("This chat was shared" in (n.get("data") or {}).get("content", "") for n in notes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
