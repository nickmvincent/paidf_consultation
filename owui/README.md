# Flywheel Sharing (OpenWebUI)

This folder contains the Flywheel conversation sharing feature and tests. It lets users preview and submit conversations to a public dataset (via Pull Request) for community curation.

Implementations
- `flywheel_action.py`: Original Action-based flow used from Chat Controls → Functions → Sharing.
- `flywheel_tool.py`: Tool-based variant exposing `Tools.share_to_flywheel(...)` for tool calling flows.
- `flywheel_filter.py`: Filter-based variant that renders the same preview/result as assistant messages from the outlet hook.
- `flywheel_pipe.py`: Pipe-based variant that returns the preview/result directly from `Pipe.pipe(...)`.
- `flywheel_shared.py`: Shared templates, types, and helpers used by all variants to keep behavior identical.

Behavior summary
- First run: produces a markdown preview with a JSON payload fenced between sentinels `<<<SHARE_PREVIEW_START>>>` … `<<<SHARE_PREVIEW_END>>>` and a clear “Next Step” instruction.
- Confirm run: refreshes tags/feedback just-in-time, computes attribution and privacy, then either creates a PR (when credentials are configured) or shows a Test Mode preview.
- Attribution modes: `anonymous`, `pseudonym` (deterministic), and `huggingface` (user token). App-level token is supported for submissions via the app account.

Valves
- Global (Valves): `default_hf_token`, `dataset_repo`, `sanity_check_repo`, `min_messages`, `max_messages`, `faq_url`, `privacy_policy_url`.
- Per-user (UserValves): `public_sharing_available`, `attribution_mode`, `license_intent`, `license_intent_note`, `ai_thoughts`, `hf_user_token`.

Using each variant
- Action: Trigger via Chat Controls → Functions → Sharing. Follow the on-screen preview/confirm flow.
- Tool: Call `Tools.share_to_flywheel(confirm=False, __chat_id__, __messages__, __user__)` to preview. Call again with `confirm=True` to submit.
- Filter: Enable the filter and press the Sharing function; the outlet injects the same preview/result as assistant messages. Confirm by pressing again.
- Pipe: Create a pipeline using `Pipe.pipe(body, __user__, __chat_id__, __messages__)`; first call previews, second call (after preview is present) submits.

Tests
- `tests.py`: Unit tests covering helper behavior and full flows for Action, Tool, Filter, and Pipe variants using a temporary SQLite DB.
- `test_privary_patterns.py`: Validates the privacy detection regexes and saves a summary to `test_results.json`.

Notes
- The Tool/Filter/Pipe variants reuse logic via `flywheel_shared.py` to stay consistent with the Action behavior and templates.
- If desired, `flywheel_action.py` can be refactored to import the shared helpers to fully deduplicate logic.
- Data access: When running inside OpenWebUI, data (chat, tags, feedbacks) is read via the in-process models (`open_webui.models.chats/feedbacks`) and not by direct SQL queries. In standalone tests or environments without the OpenWebUI backend loaded, the code transparently falls back to reading the local SQLite file for test isolation.

Build (standalone scripts)
- Some OpenWebUI installs load single-file plugins via the admin panel and cannot resolve local imports.
- Run `python3 owui/build_flywheel_standalone.py` to generate import-free standalone files in `owui/dist/`:
  - `flywheel_action.standalone.py`
  - `flywheel_tool.standalone.py`
  - `flywheel_filter.standalone.py`
  - `flywheel_pipe.standalone.py`
- You can paste/upload these standalone files directly in the OpenWebUI admin panel without needing `flywheel_shared.py` present.
