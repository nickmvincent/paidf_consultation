# Public AI Flywheel — FAQ

This FAQ explains how sharing works, available licenses and AI preference signals, and how Creative Commons (CC) Signals and the Responsible AI Standard for Licensing (RSL) relate to your choices.

## AI Preference (CC Signals)

We use CC Signals to express your preferences for AI training and use. These are machine‑readable “Content‑Usage expressions.” In the UI you’ll pick from a dropdown of common options:

- train-genai=n: Deny training.
- train-genai=n;exceptions=cc-cr: Allow training with Credit (attribution).
- train-genai=n;exceptions=cc-cr-dc: Allow with Credit + Direct Contribution reciprocity.
- train-genai=n;exceptions=cc-cr-ec: Allow with Credit + Ecosystem reciprocity.
- train-genai=n;exceptions=cc-cr-op: Allow with Credit + Open reciprocity.
- ai-use=n: Deny AI use.
- ai-use=n;exceptions=cc-cr: Allow AI use with Credit (attribution).
- ai-use=n;exceptions=cc-cr-dc: Allow with Credit + Direct Contribution reciprocity.
- ai-use=n;exceptions=cc-cr-ec: Allow with Credit + Ecosystem reciprocity.
- ai-use=n;exceptions=cc-cr-op: Allow with Credit + Open reciprocity.

Why “Ecosystem reciprocity” by default? It encourages attribution and asks downstream users to contribute improvements back to the broader tooling/data ecosystem, aligning with community benefit while remaining practical for reuse.

Learn more:
- CC Signals overview: https://creativecommons.org/ai/cc-signals/

## RSL (Responsible AI Standard for Licensing)

RSL is a complementary community effort to make AI‑relevant usage terms clearer and interoperable. We plan to integrate RSL signals for side‑by‑side clarity with CC Signals.

- RSL Standard: https://rslstandard.org/
- Status here: Integration is coming; today we record CC Signals in the dropdown and document your choice in PRs.

## Licenses

You can select a license for the content you share:
- CC0‑1.0: Public‑domain dedication.
- CC‑BY‑4.0: Attribution required.
- CC‑BY‑SA‑4.0: Attribution + share‑alike.

CC Signals and the license target different layers: the license governs legal permissions; CC Signals articulate AI‑specific usage preferences for training/use. We record both in your contribution.

## What is shared?

- The selected chat messages (cleaned of non‑essential metadata), your tags, and your selected license and AI preference are included in the PR.
- We also include a content hash for de‑duplication and integrity.
- We run heuristic privacy checks and show counts in the preview; please review before sharing.

## Can I change my mind later?

You can delete chats locally at any time. Once merged into a public dataset via PR, removal requires a follow‑up PR or maintainer request. Be careful and review the preview.

## Where can I learn more or give feedback?

Open an issue or PR in this repo. We’re especially interested in feedback on consent, privacy tooling, moderation workflows, and attribution options.
