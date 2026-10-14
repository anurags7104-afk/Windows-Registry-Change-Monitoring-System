#!/usr/bin/env python3
"""
main.py
-------
Entry point / orchestrator for the Windows Registry Change Monitoring
System. This ties together every module in the order from the
project's flowchart:

    Load Config -> Baseline -> Monitor -> Detect Changes
    -> Compare with Malware Patterns -> Alerts/Logs -> Report

Usage:
    python main.py baseline          # capture a fresh clean baseline
    python main.py scan              # one-shot: compare now vs baseline
    python main.py monitor [N]       # loop: re-scan every N seconds (default 10)

On real Windows, this reads the real registry automatically. On any
other OS (for development/demo), it transparently uses a simulated
mock registry (modules/mock_registry.json) — see modules/registry_access.py.
"""

import sys
import time

from modules import registry_access, baseline, change_detector, risk_scorer, alerting, report_generator


def do_baseline():
    print(f"[*] Mode: {registry_access.mode()}")
    print("[*] Capturing baseline snapshot of monitored registry keys...")
    snap = baseline.capture_baseline("baseline")
    total_values = sum(len(v) for v in snap["keys"].values())
    print(f"[+] Baseline captured: {len(snap['keys'])} keys, {total_values} values tracked.")
    print(f"[+] Saved to baselines/baseline.json")


def do_scan(verbose: bool = True) -> dict:
    base = baseline.load_baseline("baseline")
    current = baseline.capture_current_state()

    raw_changes = change_detector.diff_snapshots(base, current)
    analyzed = change_detector.analyze_changes(raw_changes)
    result = risk_scorer.score_all(analyzed)

    if verbose:
        alerting.print_alerts(result["changes"])

    if result["changes"]:
        log_path = alerting.log_changes(result["changes"])
        if verbose:
            print(f"[*] Changes logged to {log_path}")

    report_path = report_generator.generate_report(result, registry_access.mode())
    if verbose:
        print(f"[*] Report written to {report_path}")
        print(f"[*] Overall severity: {result['overall_severity']} "
              f"(score {result['overall_score']}/100)")

    return result


def do_monitor(interval_seconds: int):
    print(f"[*] Mode: {registry_access.mode()}")
    print(f"[*] Monitoring every {interval_seconds}s. Press Ctrl+C to stop.")
    try:
        while True:
            print(f"\n--- Scan at {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
            do_scan(verbose=True)
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1]

    if command == "baseline":
        do_baseline()
    elif command == "scan":
        do_scan()
    elif command == "monitor":
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        do_monitor(interval)
    else:
        print(f"Unknown command: {command}")
        print(__doc__)


if __name__ == "__main__":
    main()
