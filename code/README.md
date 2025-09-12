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

