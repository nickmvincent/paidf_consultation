# Public AI Flywheel (OpenWebUI Plugin)

This repository includes an OpenWebUI action (`owui_action_and_tests/flywheel.py`) that lets users share selected chats to a public Hugging Face dataset via PRs.

## Message Cleaning Behavior

- The action trims injected consent/preview text only from the last message in a chat.
- It searches for the start of the built‑in templates and keeps only the content before them:
  - `# Share Chat Publicly (Hugging Face)` (setup/consent screen)
  - `# Ready to Share:` (preview header)
- If the last message becomes empty after trimming, it is omitted from the shared payload.

This approach avoids cutting off legitimate earlier conversation while ensuring that first‑time consent or preview messages aren’t included in shared data.

## Follow‑ups / Known Gaps

- Tool calls and more advanced message shapes: for now, we preserve only a few common fields (`id`, `model`, `tool_calls`) when present. We should add richer handling for tool call results, intermediate content, and any assistant function outputs to ensure faithful reconstruction. Tests should cover these cases.
- Backward compatibility: if older injected messages appear in positions other than the last message, we may still include them. Future iterations should consider a more robust provenance tag.

