"""Audit log: append JSONL entries per audit decision, query by filter."""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from bashguard.models import Verdict

DEFAULT_LOG_PATH = Path.home() / ".bashguard" / "audit.jsonl"


def log_verdict(verdict: Verdict, command: str, log_path: Path = DEFAULT_LOG_PATH) -> None:
    """Append one JSONL line recording the audit decision."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "verdict": verdict.verdict.value.lower(),
        "message": verdict.message,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value.lower(),
                "action_type": f.action_type.value,
                "message": f.message,
                "matched_text": f.matched_text,
            }
            for f in verdict.findings
        ],
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def read_log(
    log_path: Path = DEFAULT_LOG_PATH,
    decision: str | None = None,
    rule_id: str | None = None,
    limit: int | None = None,
) -> Iterator[dict]:
    """Yield log entries, optionally filtered. limit returns most-recent N."""
    if not log_path.exists():
        return

    with log_path.open("r", encoding="utf-8") as fh:
        lines = fh.readlines()

    # Parse and filter
    entries: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if decision is not None and entry.get("verdict") != decision:
            continue

        if rule_id is not None:
            finding_ids = {f.get("rule_id") for f in entry.get("findings", [])}
            if rule_id not in finding_ids:
                continue

        entries.append(entry)

    # Apply limit from the end (most recent)
    if limit is not None:
        entries = entries[-limit:]

    yield from entries
