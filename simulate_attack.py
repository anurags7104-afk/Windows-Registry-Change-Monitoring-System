#!/usr/bin/env python3
"""
simulate_attack.py
-------------------
DEMO / TESTING SCRIPT ONLY. Not part of the monitoring toolkit itself.

This simulates what a few real malware families typically do to the
registry, so you can show your toolkit detecting them. It only
touches modules/mock_registry.json (safe, simulated) — it never
touches a real registry, even if you ran this on a real Windows box
(registry_access.write_key_value() refuses to run in REAL_REGISTRY mode).

Run this AFTER `python main.py baseline`, then run `python main.py scan`
to see the detections.

Usage:
    python simulate_attack.py autorun     # adds a suspicious autorun entry
    python simulate_attack.py defender    # "disables" Windows Defender
    python simulate_attack.py shell       # replaces the login shell
    python simulate_attack.py all         # does all three
"""

import sys
from modules import registry_access as reg


def attack_autorun():
    print("[sim] Adding malicious-looking autorun entry (HKCU\\...\\Run)...")
    reg.write_key_value(
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "WindowsUpdateHelper",
        r"C:\Users\User\AppData\Local\Temp\svchost32.exe -silent",
    )


def attack_defender():
    print("[sim] Flipping DisableAntiSpyware -> 1 (simulated Defender tampering)...")
    reg.write_key_value(
        "HKLM",
        r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
        1,
    )


def attack_shell():
    print("[sim] Replacing Winlogon Shell value (persistence technique)...")
    reg.write_key_value(
        "HKCU",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
        r"explorer.exe, C:\Users\User\AppData\Roaming\svc.exe",
    )


ATTACKS = {
    "autorun": attack_autorun,
    "defender": attack_defender,
    "shell": attack_shell,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in list(ATTACKS) + ["all"]:
        print(__doc__)
        return

    if reg.REAL_REGISTRY:
        print("[!] Refusing to run: this script only runs in simulation mode, "
              "to avoid ever touching a real machine's registry.")
        return

    choice = sys.argv[1]
    if choice == "all":
        for fn in ATTACKS.values():
            fn()
    else:
        ATTACKS[choice]()

    print("[sim] Done. Now run: python main.py scan")


if __name__ == "__main__":
    main()
