"""
baseline.py
-----------
STEP 2 of the pipeline: Baseline Creation + Registry Integrity Checker.

A "baseline" is just a snapshot of what all the monitored keys looked
like at a known-good point in time (e.g. right after setting up a
clean machine). Later, we compare the CURRENT state to this snapshot
to spot anything that changed.
"""

import json
import os
from datetime import datetime, timezone

from modules import registry_access
from modules.sensitive_keys import ALL_MONITORED_KEYS

BASELINE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "baselines")


def capture_baseline(label: str = "baseline") -> dict:
    """
    Reads every monitored key's current values and saves them as a
    timestamped JSON baseline file. Returns the snapshot dict too.
    """
    os.makedirs(BASELINE_DIR, exist_ok=True)

    snapshot = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mode": registry_access.mode(),
        "keys": {},
    }

    for key_def in ALL_MONITORED_KEYS:
        hive, path = key_def["hive"], key_def["path"]
        values = registry_access.read_key_values(hive, path)
        snapshot["keys"][f"{hive}\\{path}"] = values

    out_path = os.path.join(BASELINE_DIR, f"{label}.json")

    # Write atomically: build the JSON text fully in memory first, then
    # write it to a temp file and rename it into place. This means a
    # crash or serialization error can never leave a half-written,
    # corrupted baseline.json behind (as a direct `json.dump(..., f)`
    # can if it fails partway through serializing).
    content = json.dumps(snapshot, indent=2)
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(content)
    os.replace(tmp_path, out_path)

    return snapshot


def load_baseline(label: str = "baseline") -> dict:
    path = os.path.join(BASELINE_DIR, f"{label}.json")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No baseline found at {path}. Run `python main.py baseline` first."
        )
    with open(path) as f:
        return json.load(f)


def capture_current_state() -> dict:
    """Same shape as a baseline snapshot, but not saved to disk."""
    state = {"keys": {}}
    for key_def in ALL_MONITORED_KEYS:
        hive, path = key_def["hive"], key_def["path"]
        state["keys"][f"{hive}\\{path}"] = registry_access.read_key_values(hive, path)
    return state
