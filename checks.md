**Manual Tests**
- Setup flow: With sharing disabled, clicking action shows setup instructions; enable `public_sharing_available` and retry to see preview flow. [Covered by tests]
- Attribution modes: Switch `anonymous`, `pseudonym`, `manual_hf`; verify attribution text in preview/result changes accordingly; `manual_hf` uses mock mode. [Partially covered] — pseudonym and manual_hf paths tested; still verify anonymous label manually.
- License + AI preference: Change license and Content-Usage expression; confirm they appear in preview JSON and PR description. [Manual high priority]
- Last-message trimming: Append consent heading `# Share Chat Publicly (Hugging Face)` to a normal assistant reply; verify only content before heading is shared. Repeat with `# Ready to Share:`. If trimming empties the last message, it is dropped. [Manual high priority]
- Min/max messages: Chats below `min_messages` show a warning; above `max_messages` show a warning and block sharing. [Covered by tests]
- Tags and feedback: Add/remove tags and thumbs up/down; build preview, then change tags/feedback and proceed to confirm; verify tag/feedback counts refresh before submission and toast appears. [Covered by tests]
- Response labels: Give ratings on specific assistant messages; verify `response_labels` indexes match cleaned message positions and message IDs when present. [Manual high priority]
- Privacy scan: Paste test PII (dummy emails, phone numbers, IBAN, credit cards that pass Luhn); preview shows counts and types; ensure no blocking, only warnings. [Partially covered] — detection function tested; verify preview wiring manually.
- Preview JSON extraction: Ensure the preview contains the JSON block with `<<<SHARE_PREVIEW_START/END>>>` and that confirm run consumes it. [Covered by tests]
- Duplicate guard: Share once, immediately share again; observe duplicate warning with link to prior PR; after 5 minutes window, allow again. [Covered by tests]
- HF creds missing: Without `default_hf_token` or missing `huggingface_hub`, confirm mock result appears with instructions. [Manual routine]
- HF preflight failure: Use a bad token or repo; verify clear preflight error listing issues and token identity if available. [Covered by tests]
- Real PR path: With valid token and repo, confirm PR is created, file path `contributions/<id>.json` exists, and PR description fields are filled. [Covered by tests (mocked PR creation)] — still manually verify with real token once per release.
- DB tags merge: Place tags in `chatidtag`, `chat.meta.tags`, and `chat.tags` in payload; verify normalized, deduplicated union shows in preview and PR. [Manual routine]
- Non-text messages: Verify non-string contents are ignored for trimming but included structurally as-is. [Covered by tests (basic)] — still sanity check in UI when last message is non-string. [Manual routine]
- Tool calls (current behavior): If present, they are preserved as-is, but no special reconstruction; note this in demo as a known limitation. [Covered by tests (basic preservation)] — advanced flows pending.

**Demo Video Plan**
- Overview: Show the chat, open Controls → Valves → Functions → Sharing, enable sharing.
- Consent and setup: Trigger the action with sharing off (shows setup), then enable and trigger again.
- Preview tour: Walk through the preview header, tags/feedback section, privacy scan counts, and the exact Share Preview JSON.
- Trimming behavior: Demonstrate an assistant reply followed by the consent heading and show that only the real reply content is captured in the preview JSON.
- Tags/feedback refresh: Add a tag and a thumbs up, rebuild preview, then confirm run to show the toast about refreshed counts.
- Attribution modes: Switch anonymous → pseudonym → manual_hf; rebuild preview to show different attribution.
- License and AI preference: Change them and show they appear in preview and PR description.
- Mock vs. real submission: First, with no token, show the mock result; then add a valid HF token and dataset repo and perform a real PR, clicking the PR link.
- Duplicate guard: Attempt to share the same chat twice in a row and show the duplicate warning.
- Closing notes: Mention privacy scan is heuristic, and users should review content before sharing.

**Call for Feedback**
- We’re experimenting with a community-moderated “flywheel” for sharing selected chats publicly via PRs. The goal is to build better public AI datasets with transparent licensing and clear AI-use preferences. Please try it out and share what feels confusing, risky, or missing. Ideas welcome on: better preview UX, stronger privacy tooling, moderation workflows, and attribution options. Open an issue or PR with your thoughts.

**Future Option: Differential Privacy via OpenMined Datasite**
- In addition to public, per-chat sharing, we’re exploring a privacy-preserving option where contributions are aggregated and released with differential privacy guarantees using OpenMined’s Datasite. Contributors would opt into a separate “DP Pool,” where their data informs aggregate statistics or model updates without revealing individual messages. This pathway would include: pre-aggregation privacy filters, DP budget accounting, and transparent release policies. If this direction interests you, let us know — we are looking for early collaborators and use cases.
