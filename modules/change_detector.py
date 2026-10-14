"""
change_detector.py
-------------------
STEP 4 of the pipeline: Change Analysis.

Compares two snapshots (baseline vs current) and works out exactly
what was added, removed, or modified — then checks each change
against known malware behavior patterns.
"""

import re
from modules.sensitive_keys import (
    SECURITY_POLICY_KEYS,
    SUSPICIOUS_VALUE_PATTERNS,
    EXPECTED_SHELL_VALUE,
)


def diff_snapshots(old_snapshot: dict, new_snapshot: dict) -> list:
    """
    Returns a list of change dicts, each like:
    {
        "key": "HKCU\\Software\\...\\Run",
        "value_name": "Updater",
        "change_type": "added" | "removed" | "modified",
        "old_value": ... ,
        "new_value": ...,
    }
    """
    changes = []
    old_keys = old_snapshot.get("keys", {})
    new_keys = new_snapshot.get("keys", {})

    all_key_paths = set(old_keys.keys()) | set(new_keys.keys())

    for key_path in sorted(all_key_paths):
        old_values = old_keys.get(key_path, {})
        new_values = new_keys.get(key_path, {})
        all_value_names = set(old_values.keys()) | set(new_values.keys())

        for value_name in sorted(all_value_names):
            old_val = old_values.get(value_name)
            new_val = new_values.get(value_name)

            if value_name not in old_values:
                changes.append({
                    "key": key_path, "value_name": value_name,
                    "change_type": "added", "old_value": None, "new_value": new_val,
                })
            elif value_name not in new_values:
                changes.append({
                    "key": key_path, "value_name": value_name,
                    "change_type": "removed", "old_value": old_val, "new_value": None,
                })
            elif old_val != new_val:
                changes.append({
                    "key": key_path, "value_name": value_name,
                    "change_type": "modified", "old_value": old_val, "new_value": new_val,
                })

    return changes


def classify_change(change: dict) -> dict:
    """
    Attach a 'flags' list and a 'malware_pattern' note (if any) to a
    single change dict, based on our known-bad patterns.
    """
    flags = []
    key_lower = change["key"].lower()
    new_val = str(change.get("new_value") or "")

    # 1. Autorun additions are always worth a look.
    if "\\run" in key_lower and change["change_type"] == "added":
        flags.append("NEW_AUTORUN_ENTRY")

    # 2. Does the new value match a known-bad command pattern?
    for pattern in SUSPICIOUS_VALUE_PATTERNS:
        if re.search(pattern, new_val, re.IGNORECASE):
            flags.append(f"SUSPICIOUS_PATTERN: matches '{pattern}'")

    # 3. Security policy key tampering (Defender/Firewall/UAC/Shell).
    for sec_key in SECURITY_POLICY_KEYS:
        full_path = f"{sec_key['hive']}\\{sec_key['path']}"
        if change["key"] == full_path and change["value_name"] == sec_key["watch_value"]:
            flags.append(f"SECURITY_POLICY_CHANGE: {sec_key['meaning']}")

            # Special case: shell replacement
            if sec_key["watch_value"] == "Shell" and new_val.lower() != EXPECTED_SHELL_VALUE:
                flags.append(f"SHELL_REPLACED: expected '{EXPECTED_SHELL_VALUE}', got '{new_val}'")

    change["flags"] = flags
    return change


def analyze_changes(changes: list) -> list:
    return [classify_change(c) for c in changes]
