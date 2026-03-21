"""
bashguard.audit_stats — Aggregate statistics from the JSONL audit log.

Inspired by n2-ark's ark.stats(days?) method.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bashguard.audit_log import DEFAULT_LOG_PATH


def compute_stats(
    log_path: Path = DEFAULT_LOG_PATH,
    days: int | None = None,
) -> dict:
    """Compute aggregate stats from the audit log.

    Returns dict with: total, by_verdict, by_rule, block_rate.
    """
    if not log_path.exists():
        return {"total": 0, "by_verdict": {}, "by_rule": {}, "block_rate": 0.0}

    cutoff = None
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    verdict_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    total = 0

    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Date filter
            if cutoff is not None:
                ts_str = entry.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str)
                    if ts < cutoff:
                        continue
                except (ValueError, TypeError):
                    continue

            total += 1
            verdict_counts[entry.get("verdict", "unknown")] += 1

            for finding in entry.get("findings", []):
                rule_id = finding.get("rule_id", "")
                if rule_id:
                    rule_counts[rule_id] += 1

    block_count = verdict_counts.get("block", 0)
    block_rate = block_count / total if total > 0 else 0.0

    return {
        "total": total,
        "by_verdict": dict(verdict_counts),
        "by_rule": dict(rule_counts),
        "block_rate": block_rate,
    }
