# Windows Registry Change Monitoring System

A toolkit that detects unauthorized or malware-like changes to Windows
registry keys commonly abused for persistence and security-tool
tampering (autorun keys, Defender/Firewall/UAC policy keys, shell
hijacking).

## How it maps to the project spec

| Spec section | Implemented in |
|---|---|
| Define Sensitive Registry Keys | `modules/sensitive_keys.py` |
| Baseline Creation | `modules/baseline.py` → `python main.py baseline` |
| Continuous Monitoring (polling) | `main.py monitor [interval]` |
| Change Analysis (add/modify/delete) | `modules/change_detector.py` |
| Malware behavior pattern matching | `change_detector.classify_change()` |
| Risk scoring | `modules/risk_scorer.py` |
| Alerting & Logging (CSV, timestamped) | `modules/alerting.py` → `output/registry_change_log.csv` |
| Final Reporting | `modules/report_generator.py` → `output/registry_report_*.md` |

## Two run modes (important — read this)

`winreg`, the library used to read the real Windows registry, **only
exists on Windows**. To make this project buildable/demoable anywhere
(and safe to test attack-simulation on), `modules/registry_access.py`
auto-detects the platform:

- **On a real Windows machine:** automatically reads the real
  registry. No code changes needed — just run it.
- **Anywhere else (Mac/Linux, or Windows without admin rights):**
  automatically falls back to a simulated registry stored in
  `modules/mock_registry.json`, so the whole pipeline — baseline,
  detection, scoring, alerting, reporting — still runs and can be
  demoed/tested.

The tool prints which mode it's in every time you run it, and your
final report records it too — so there's no ambiguity about which
mode produced which results.

**This toolkit is read-only by design.** It never writes to the real
registry — `write_key_value()` refuses to run outside simulation mode.
That's deliberate: a monitoring tool shouldn't also be able to modify
the thing it's supposed to be watching over.

## Usage

```bash
# 1. Capture a clean baseline (do this first, on a trusted system state)
python main.py baseline

# 2. Run a one-off scan comparing current state to baseline
python main.py scan

# 3. Or monitor continuously (re-scans every N seconds, default 10)
python main.py monitor 30
```

### Demoing detection (simulation mode only)

Since you likely don't want to actually disable Defender or add real
malware-style autorun entries on your machine, `simulate_attack.py`
safely fakes these changes **only inside the mock registry file**:

```bash
python main.py baseline
python simulate_attack.py all      # or: autorun / defender / shell
python main.py scan                # watch it get flagged
```

This is exactly how you'd generate the "Examples" the spec asks for:
> New autorun entry detected / Registry key altered: Windows Defender
> disabled / Integrity failure: Value mismatch from baseline

### Running for real on Windows

On an actual Windows machine, just run the same commands —
`registry_access.py` will detect `winreg` is available and read your
real registry automatically. Run `main.py baseline` once on a clean
machine, then `main.py monitor` to watch it live. (You will **not**
be able to run `simulate_attack.py` there — it intentionally refuses
to run outside simulation mode.)

## Output

- `baselines/baseline.json` — the saved clean snapshot
- `output/registry_change_log.csv` — timestamped change log (old
  value, new value, severity, matched flags) — open this in Excel for
  your report screenshots
- `output/registry_report_<timestamp>.md` — full markdown report per
  scan, with severity breakdown and mitigation recommendations

## Project structure

```
registry_monitor/
├── main.py                  # CLI entry point / orchestrator
├── simulate_attack.py       # demo/test script (simulation mode only)
├── modules/
│   ├── sensitive_keys.py    # which registry keys/patterns we watch
│   ├── registry_access.py   # real winreg OR simulated backend
│   ├── baseline.py          # snapshot capture/load
│   ├── change_detector.py   # diff + malware pattern matching
│   ├── risk_scorer.py       # severity scoring
│   ├── alerting.py          # console alerts + CSV logging
│   ├── report_generator.py  # markdown report generation
│   └── mock_registry.json   # simulated registry state (non-Windows/demo)
├── baselines/                # saved baseline snapshots
└── output/                   # logs + reports generated per run
```

## Extending it further (optional, for a stronger submission)

- Add more keys to `AUTORUN_KEYS`/`SECURITY_POLICY_KEYS` in
  `sensitive_keys.py` (e.g. `Image File Execution Options` debugger
  hijacking, scheduled-task-adjacent keys).
- Add `hashlib`-based integrity hashing of each key's full value set,
  stored alongside the baseline, as an extra tamper-evidence layer.
- Wire `main.py monitor` into Windows Task Scheduler for always-on
  monitoring (the spec's "optional monitoring automation").
