# Public AI Flywheel (OpenWebUI Plugin)

This repository includes an "open mini book" on Public AI Data Flywheel and an example implementation: an OpenWebUI action (`owui_action_and_tests/flywheel.py`) that lets users share selected chats to a public Hugging Face dataset via PRs.

## Book: Data Flywheels and Public AI

The `book/` folder contains a Quarto mini‑book describing the rationale, MVP, governance, and data model for public AI flywheels. Read the book on the GitHub pages page: https://nickmvincent.github.io/paidf_consultation/ 

- Structure: see `book/_quarto.yml` for chapters. Output renders to `book/docs/`.
- Formal model: `book/01i_record_generation_model.qmd` defines a small staged model for how interactions become public (or private) records (capture, prompt, consent, checks, publish).
- Preview locally: `quarto render book/` then open `book/docs/index.html`.

### Contributing to the Book

- Edits: submit PRs that modify `.qmd` files in `book/`. Keep prose concise; avoid filler; prefer examples and clear definitions.
- Callouts: for "asides" or "slightly technical sidenotes" use Quarto collapsed callouts:
  
  ```
  ::: {.callout-note collapse=true title="Model Reference (01i)"}
  ... concise mapping to stages/fields ...
  :::
  ```
- Citations: use `book/references*.bib` where appropriate.

### Feedback and Areas for Critique

- Model assumptions: stage definitions (`E_i, C_i, S_i, A_i, T_i, P_i^k, M_i`), independence, and measurability.
- Consent UX: prompt timing (`q_i`), defaults, and how they affect `p_a` without spamming.
  - More generally, balancing informativeness and friction
- Validation: what belongs in `T_i` (PII rules, schema checks) and failure handling.
- Licensing and signals: defaults for `L_i` and `U_i` (e.g., `train-genai=n;exceptions=cc-cr`), enforcement expectations, and tooling.
- Attribution: pseudonym design and linkability trade‑offs; anonymous option implications.
- PR workflow: triage, quarantine, merge policy, and public provenance.
- Data shape: schema `ψ(x_i)` fields required vs optional; hashing and provenance.
- Metrics: definitions for throughput and stage yields; what to publish on dashboards.

How to give feedback: open a GitHub Issue with a focused title (prefix with “Book: …”), reference file paths (e.g., `book/2a_mvp.qmd`), and propose specific edits or questions. PRs with small, surgical changes are welcome.

Or just ping on Slack, email, socials, etc. :)
