#!/usr/bin/env python3
"""
Simple build step to produce standalone versions of Flywheel plugins with
flywheel_shared injected inline. This helps installation via the OpenWebUI
admin panel where relative imports may not resolve.

Usage:
  python3 owui/build_flywheel_standalone.py

Outputs:
  owui/dist/flywheel_action.standalone.py
  owui/dist/flywheel_tool.standalone.py
  owui/dist/flywheel_filter.standalone.py
  owui/dist/flywheel_pipe.standalone.py
"""

from __future__ import annotations

import re
from pathlib import Path


def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def write_text(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")


def strip_future_imports(s: str) -> str:
    lines = s.splitlines()
    out = [ln for ln in lines if not ln.strip().startswith("from __future__ import")]
    return "\n".join(out) + ("\n" if s.endswith("\n") else "")


def remove_shared_imports(lines: list[str]) -> list[str]:
    out = []
    pattern = re.compile(r"\b(flywheel_shared)\b")
    for ln in lines:
        if "import" in ln and pattern.search(ln):
            # drop this line
            continue
        out.append(ln)
    return out


def find_insert_position(lines: list[str]) -> int:
    # After header docstring and any from __future__ imports
    i = 0
    n = len(lines)
    # skip shebang / empty
    while i < n and lines[i].strip() == "":
        i += 1
    # header docstring
    if i < n and lines[i].lstrip().startswith('"""'):
        triple = '"""'
        # find end of docstring
        i += 1
        while i < n and triple not in lines[i]:
            i += 1
        if i < n:
            i += 1
    # skip blank lines
    while i < n and lines[i].strip() == "":
        i += 1
    # include any __future__ imports
    last_future = -1
    j = i
    while j < n:
        if lines[j].strip().startswith("from __future__ import"):
            last_future = j
            j += 1
            continue
        break
    return (last_future + 1) if last_future >= 0 else i


def build_standalone(src: Path, shared: str) -> str:
    content = read_text(src)
    lines = content.splitlines()
    lines = remove_shared_imports(lines)
    insert_pos = find_insert_position(lines)
    shared_injected = strip_future_imports(shared)
    combined = lines[:insert_pos] + ["\n# ===== Begin injected flywheel_shared =====\n", shared_injected, "\n# ===== End injected flywheel_shared =====\n"] + lines[insert_pos:]
    return "\n".join(line if isinstance(line, str) else line for line in combined)


def main():
    base = Path(__file__).parent
    shared_path = base / "flywheel_shared.py"
    shared = read_text(shared_path)

    targets = [
        (base / "flywheel_action.py", base / "dist" / "flywheel_action.standalone.py"),
        (base / "flywheel_tool.py", base / "dist" / "flywheel_tool.standalone.py"),
        (base / "flywheel_filter.py", base / "dist" / "flywheel_filter.standalone.py"),
        (base / "flywheel_pipe.py", base / "dist" / "flywheel_pipe.standalone.py"),
    ]

    for src, out in targets:
        built = build_standalone(src, shared)
        write_text(out, built)
        print(f"Built: {out}")


if __name__ == "__main__":
    main()

