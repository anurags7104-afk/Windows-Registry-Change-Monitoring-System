"""
sensitive_keys.py
------------------
STEP 1 of the pipeline: Define Sensitive Registry Keys.

This is just a central list of "interesting" registry locations and
known malware behavior patterns. Having this as its own file makes it
easy to add more keys later without touching the monitoring logic.

Registry basics (if you're new to this):
- HKCU = HKEY_CURRENT_USER  (settings for the logged-in user)
- HKLM = HKEY_LOCAL_MACHINE (settings for the whole machine, needs admin)
- A "key" is like a folder path, e.g. Software\\Microsoft\\Windows\\...
- A "value" is a named setting inside that key, e.g. "OneDrive" = "C:\\...\\OneDrive.exe"
"""

# --- Autorun / persistence keys ---
# Malware loves these: anything placed here runs automatically at login.
AUTORUN_KEYS = [
    {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Run"},
    {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"},
    {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\Run"},
    {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"},
    {"hive": "HKLM", "path": r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"},
]

# --- Security tool tampering keys ---
# If these change, something may be trying to blind your defenses.
SECURITY_POLICY_KEYS = [
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "watch_value": "DisableAntiSpyware",
        "meaning": "Windows Defender disabled via policy",
    },
    {
        "hive": "HKLM",
        "path": r"SYSTEM\CurrentControlSet\Services\WinDefend",
        "watch_value": "Start",
        "meaning": "Windows Defender service start-type changed (4 = disabled)",
    },
    {
        "hive": "HKLM",
        "path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "watch_value": "EnableFirewall",
        "meaning": "Windows Firewall enabled/disabled",
    },
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "watch_value": "EnableLUA",
        "meaning": "UAC (User Account Control) enabled/disabled — a classic UAC-bypass indicator",
    },
    {
        "hive": "HKCU",
        "path": r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "watch_value": "Shell",
        "meaning": "Default shell replaced (should normally be 'explorer.exe')",
    },
]

# All keys we actively poll, flattened into one list for convenience.
ALL_MONITORED_KEYS = AUTORUN_KEYS + [
    {"hive": k["hive"], "path": k["path"]} for k in SECURITY_POLICY_KEYS
]

# Value-level heuristics used by the risk scorer / change analyzer.
SUSPICIOUS_VALUE_PATTERNS = [
    r"powershell.*-enc",          # base64-encoded PowerShell payload
    r"cmd(\.exe)?\s*/c",          # shell-out via cmd
    r"\\AppData\\(Local|Roaming)\\Temp\\",  # executing from temp dirs
    r"\.vbs(\s|$)",
    r"\.ps1(\s|$)",
    r"regsvr32.*scrobj",          # "squiblydoo" technique
    r"rundll32.*javascript:",
    r"mshta\s",
]

EXPECTED_SHELL_VALUE = "explorer.exe"
