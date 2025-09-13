# Flywheel Tests (code/)

This folder contains the Flywheel function (`flywheel.py`) and two complementary test suites:

- `tests.py`: Python unittest coverage for helpers and action flows (DB-backed, no network).
- `e2e_openwebui_flywheel.py`: Playwright browser automation that drives OpenWebUI end‑to‑end.

## Python unit tests

What it covers:
- Helper utilities: tag normalization, message hashing, pseudonym generation, Luhn check, privacy scan, cleaning, and preview extraction.
- Workflow logic: setup/opt‑in, min/max message gates, preview build, refresh on tag/feedback changes, preflight failure path, PR creation path (mocked), and de‑duplication guard.

Run:
```
python3 -m unittest -q
```

Notes:
- Tests are self‑contained and use a temporary SQLite DB mirroring OpenWebUI’s tables.
- No network or external packages are required; the HuggingFace path is safely mocked.

## Playwright end‑to‑end test

Script: `e2e_openwebui_flywheel.py`

Pre‑requisites:
- OpenWebUI running at `http://localhost:8080` with the Flywheel function available.
- Python Playwright installed locally:
  ```
  pip install playwright
  playwright install
  ```

What it does:
- Opens OpenWebUI, navigates to Controls → Functions → “Share to Flywheel”.
- Attempts to enable opt‑in and set attribution to `manual_hf` (test mode) if visible.
- Clicks Share to generate a preview, waits for preview markers, then clicks Share again.
- Accepts any of these outcomes: Test Mode preview, PR created, or preflight error.

Run:
```
python e2e_openwebui_flywheel.py
```

Tips:
- If your OpenWebUI instance requires auth, log in beforehand and keep the session active.
- If your UI labels differ, adjust selectors or add test IDs; the script favors text‑based selectors and includes fallbacks.
- Default target URL is hardcoded (`BASE_URL` in the script). Change it if your instance runs elsewhere.

## Usage Flows

This summarizes the primary user flows for the Flywheel action (`flywheel.py`). It reflects the current implementation and intended UX.

- Consent off: Opt‑in disabled
  - Open action → shows a short setup screen explaining how to enable sharing, pick attribution, license, and AI Preference, with links to Data FAQ and Privacy Policy.
  - No preview or PR is created until `opt_in_enabled = True`.

- Consent on: First click (preview)
  - Runs privacy scan; enforces min/max message counts.
  - Builds a preview that includes: assessment (good/bad/mixed from feedback counts), message count, attribution display, AI Preference, tags, feedback samples, and a public sharing warning (Researcher Access note shown only if ON).
  - Normalizes tags from all sources (DB `chatidtag`, `chat.meta.tags`, and `chat.chat.tags`).
  - Creates a Share Preview JSON block with the exact contribution payload (including `response_labels`, which map specific assistant messages to good/bad using feedback `meta.message_id` or `meta.message_index`).

- Consent on: Second click (confirm + send)
  - Just‑in‑time refresh: re‑reads tags and feedback for the chat, recomputes assessment, and updates the payload before sending.
  - If tags/feedback changed since preview, shows a small success toast (“Latest tags/feedback grabbed …”) and proceeds without requiring another click.
  - Test mode if either (a) `attribution_mode = manual_hf` or (b) no valid Hugging Face credentials; otherwise attempts a real PR.
  - If `sanity_check_repo = True` and credentials exist, runs preflight; on failure, shows an error notification and stops.
  - On successful PR creation, shows a confirmation with link and records a de‑dup guard for 5 minutes to avoid repeat submissions.

- Attribution modes
  - Anonymous: `attribution = "Anonymous"`.
  - Pseudonym: deterministic handle derived from `__user__.id` (stable, unsalted).
  - Manual HF: contribution is simulated (test mode); power users can later create PRs manually.

- Researcher Access toggle
  - OFF: public warning is concise (“You are about to share public dataset data.”).
  - ON: appends a note indicating research team may privately analyze non‑temporary, non‑deleted chats for evaluation/R&D.

- Edge cases and guards
  - Too short/long: preview will not build until message count is within `[min_messages, max_messages]`.
  - Dedup: attempting to share the same chat within ~5 minutes after a successful PR shows a warning with a link to the prior PR.
  - Errors: invalid preview JSON or PR creation errors are surfaced as notifications.

