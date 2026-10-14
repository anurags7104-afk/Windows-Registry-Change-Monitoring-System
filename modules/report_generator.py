"""
report_generator.py
--------------------
STEP 6: Final Reporting.

Builds a human-readable Markdown report summarizing one monitoring
run — this is what you turn into the "Project documentation" / PPT
screenshots for your submission.
"""

import os
from datetime import datetime, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")


def generate_report(scored_result: dict, mode_str: str) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(OUTPUT_DIR, f"registry_report_{timestamp}.md")

    lines = []
    lines.append("# Windows Registry Change Monitoring Report")
    lines.append("")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- **Mode:** {mode_str}")
    lines.append(f"- **Total changes detected:** {scored_result['total_changes']}")
    lines.append(f"- **Overall severity:** {scored_result['overall_severity']} "
                  f"(score {scored_result['overall_score']}/100)")
    lines.append("")

    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = scored_result["counts_by_severity"].get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count} |")
    lines.append("")

    if not scored_result["changes"]:
        lines.append("No changes were detected. Registry state matches baseline.")
    else:
        lines.append("## Detected Changes")
        lines.append("")
        for c in sorted(scored_result["changes"], key=lambda x: -x["risk_score"]):
            lines.append(f"### [{c['severity']}] {c['key']} \\ {c['value_name']}")
            lines.append(f"- Change type: **{c['change_type']}**")
            lines.append(f"- Old value: `{c.get('old_value')}`")
            lines.append(f"- New value: `{c.get('new_value')}`")
            lines.append(f"- Risk score: {c['risk_score']}/100")
            if c.get("flags"):
                lines.append(f"- Flags: {', '.join(c['flags'])}")
            else:
                lines.append("- Flags: none (routine change)")
            lines.append("")

    lines.append("## Mitigation Recommendations")
    lines.append("")
    if scored_result["overall_score"] >= 40:
        lines.extend([
            "- Investigate the flagged autorun/security-policy changes immediately.",
            "- Isolate the machine from the network if a CRITICAL finding is confirmed malicious.",
            "- Re-enable any disabled security tools (Defender/Firewall) and re-check UAC settings.",
            "- Run a full AV/EDR scan and compare the entry against known-malware hash databases.",
            "- After remediation, re-capture a new clean baseline.",
        ])
    else:
        lines.extend([
            "- No high-risk indicators found in this run.",
            "- Continue periodic monitoring and keep the baseline up to date after authorized changes.",
        ])

    content = "\n".join(lines)
    with open(report_path, "w") as f:
        f.write(content)

    return report_path
