# Flywheel Sharing (OpenWebUI)

This folder contains the Flywheel conversation sharing feature and tests. It lets users preview and submit conversations to a public dataset (via Pull Request) for community curation.

Implementations
- `flywheel_action.py`: Original Action-based flow used from Chat Controls → Functions → Sharing.
- `flywheel_tool.py`: Tool-based variant exposing `Tools.share_to_flywheel(...)` for tool calling flows.
- `flywheel_filter.py`: Filter-based variant that automatically shares high/low quality chats without a preview (privacy-gated).
- `flywheel_pipe.py`: Pipe-based variant that auto-shares every N messages (privacy-gated).
- `flywheel_shared.py`: Shared templates, types, and helpers used by all variants to keep behavior identical.

Behavior summary
- Tool: preview → confirm; creates a PR when credentials are configured, or Test Mode preview without creds.
- Filter: no preview; if conversation is clearly high or low quality (based on feedback), and no obvious personal data is detected, submits automatically.
- Pipe: no preview; submits automatically whenever total cleaned messages is a multiple of `share_every_n_messages` (default 5), gated by privacy.
- Attribution modes: `anonymous`, `pseudonym` (deterministic), and `huggingface` (user token). App-level token is supported for submissions via the app account.

Valves
- Global (Valves): `default_hf_token`, `dataset_repo`, `sanity_check_repo`, `min_messages`, `max_messages`, `faq_url`, `privacy_policy_url`.
- Per-user (UserValves): `public_sharing_available`, `attribution_mode`, `license_intent`, `license_intent_note`, `ai_thoughts`, `hf_user_token`.

Using each variant
- Action: Trigger via Chat Controls → Functions → Sharing. Follow the on-screen preview/confirm flow.
- Tool: Call `Tools.share_to_flywheel(confirm=False, __chat_id__, __messages__, __user__)` to preview. Call again with `confirm=True` to submit.
- Filter: Enable the filter. When a chat is clearly high/low quality and privacy-safe, a PR is created automatically.
- Pipe: Build a pipeline and call `Pipe.pipe(body, __user__, __chat_id__, __messages__)`. A PR is created automatically every `share_every_n_messages` messages if privacy-safe.

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
