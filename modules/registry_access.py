"""
registry_access.py
-------------------
This module is the ONLY place that talks to the actual registry.
Everything else in the project calls functions from here, so the rest
of the code doesn't care whether it's running on real Windows or in
"simulation mode" (useful for development/demo on non-Windows machines,
and for your submission video if you don't have a spare Windows box to
safely test malware-like changes on).

How it decides which mode to use:
- If the `winreg` module is importable (i.e. we're really on Windows),
  we use it directly.
- Otherwise we fall back to a JSON file that pretends to be the
  registry (modules/mock_registry.json), so you can still develop,
  test, and demo the whole pipeline.

On your real Windows machine, just running this normally will
automatically use the real registry — no code changes needed.
"""

import json
import os
import sys

try:
    import winreg  # only exists on Windows
    REAL_REGISTRY = True
except ImportError:
    REAL_REGISTRY = False

MOCK_DB_PATH = os.path.join(os.path.dirname(__file__), "mock_registry.json")

_HIVE_MAP = {}
if REAL_REGISTRY:
    _HIVE_MAP = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }


def _load_mock_db() -> dict:
    if not os.path.exists(MOCK_DB_PATH):
        return {}
    with open(MOCK_DB_PATH, "r") as f:
        return json.load(f)


def _save_mock_db(db: dict) -> None:
    with open(MOCK_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def _make_json_safe(value):
    """
    winreg can hand back types json.dump() can't serialize directly:
    - REG_BINARY values come back as raw `bytes`
    - REG_MULTI_SZ values come back as a list of str (already JSON-safe)
    - REG_DWORD/REG_SZ come back as int/str (already JSON-safe)

    We convert bytes to a hex string (prefixed so we can tell it apart
    from a real string value at a glance), and leave everything else
    as-is. This keeps the data fully readable in reports/logs instead
    of silently losing binary values.
    """
    if isinstance(value, bytes):
        return f"0x{value.hex()}"
    if isinstance(value, list):
        return [_make_json_safe(v) for v in value]
    return value


def read_key_values(hive: str, path: str) -> dict:
    """
    Return {value_name: value_data} for all values under a registry key.
    Returns {} if the key doesn't exist (this is normal — not every
    machine has every autorun key populated).
    """
    if REAL_REGISTRY:
        values = {}
        try:
            with winreg.OpenKey(_HIVE_MAP[hive], path) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = _make_json_safe(data)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except PermissionError:
            # HKLM security-policy keys sometimes need admin rights to
            # enumerate fully; skip quietly rather than crashing the scan.
            pass
        return values
    else:
        db = _load_mock_db()
        return db.get(hive, {}).get(path, {})


def write_key_value(hive: str, path: str, name: str, data) -> None:
    """
    Used only by our own test/demo scripts to SIMULATE a malware-style
    change (e.g. adding a fake autorun entry) so we can prove the
    detector catches it. In mock mode this edits the JSON file; on
    real Windows this would use winreg.SetValueEx (not wired up here
    on purpose — this toolkit is a MONITOR, it should not be the thing
    modifying real security-relevant keys).
    """
    if REAL_REGISTRY:
        raise RuntimeError(
            "Writing to the real registry is disabled in this toolkit. "
            "This tool is a read-only monitor by design."
        )
    db = _load_mock_db()
    db.setdefault(hive, {}).setdefault(path, {})[name] = data
    _save_mock_db(db)


def delete_key_value(hive: str, path: str, name: str) -> None:
    if REAL_REGISTRY:
        raise RuntimeError("Writing to the real registry is disabled in this toolkit.")
    db = _load_mock_db()
    if name in db.get(hive, {}).get(path, {}):
        del db[hive][path][name]
        _save_mock_db(db)


def mode() -> str:
    return "REAL_WINDOWS_REGISTRY" if REAL_REGISTRY else "SIMULATION_MODE (mock_registry.json)"
