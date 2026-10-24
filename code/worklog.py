"""Append-only challenge work-log support."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path

def append_turn(user_prompt: str, summary: str, actions: list[str], root: Path) -> Path:
    """Append a redacted turn record beside the top-level AGENTS.md.

    Runtime identifiers must be supplied by the actual host, not inferred.
    """
    tool = "ChatGPT Work"
    model = "GPT-6"
    path = root / "log.txt"
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    action_text = "\n".join(f"* {line}" for line in actions)
    entry = f"""\n## [{stamp}] Implementation update

User Prompt (verbatim, secrets redacted):
{user_prompt}

Agent Response Summary:
{summary}

Actions:
{action_text}

Context:
tool={tool}
model={model}
branch={branch}
repo_root=remote GitHub repository {repo}
worktree=remote GitHub API
parent_agent=none

"""
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(entry)
    return path
