"""
alerting.py
-----------
STEP 5: Alert/Log Generation.

Writes a timestamped log line per change (CSV, easy to open in Excel
for your report/screenshots) and prints on-screen alerts for anything
above LOW severity.
"""

import csv
import os
from datetime import datetime, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
LOG_PATH = os.path.join(OUTPUT_DIR, "registry_change_log.csv")


def log_changes(changes: list) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    file_exists = os.path.exists(LOG_PATH)

    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp", "key", "value_name", "change_type",
                "old_value", "new_value", "severity", "risk_score", "flags",
            ])
        for c in changes:
            writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                c["key"], c["value_name"], c["change_type"],
                c.get("old_value"), c.get("new_value"),
                c.get("severity"), c.get("risk_score"),
                "; ".join(c.get("flags", [])),
            ])

    return LOG_PATH


def print_alerts(changes: list) -> None:
    if not changes:
        print("[OK] No registry changes detected since baseline.")
        return

    for c in changes:
        if c.get("severity") in ("CRITICAL", "HIGH"):
            print(
                f"[ALERT:{c['severity']}] {c['key']} :: {c['value_name']} "
                f"{c['change_type'].upper()} -> {c.get('new_value')!r} "
                f"(score {c['risk_score']}) | {', '.join(c.get('flags', [])) or 'no specific flag'}"
            )
        elif c.get("severity") == "MEDIUM":
            print(
                f"[WARN] {c['key']} :: {c['value_name']} "
                f"{c['change_type'].upper()} -> {c.get('new_value')!r}"
            )
        else:
            print(
                f"[info] {c['key']} :: {c['value_name']} "
                f"{c['change_type'].upper()}"
            )
