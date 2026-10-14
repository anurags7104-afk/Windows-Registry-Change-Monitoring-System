"""
risk_scorer.py
---------------
Assigns a severity score to each analyzed change, and an overall
score for the whole monitoring run. Same idea as the risk-scoring
step in a malware-analysis report — turns a pile of raw findings into
a single "how worried should I be" number.
"""

FLAG_WEIGHTS = {
    "NEW_AUTORUN_ENTRY": 30,
    "SECURITY_POLICY_CHANGE": 40,
    "SHELL_REPLACED": 50,
}
DEFAULT_SUSPICIOUS_PATTERN_WEIGHT = 25
BASE_MODIFIED_WEIGHT = 5   # any unflagged change still gets a small score
BASE_REMOVED_WEIGHT = 10   # unexplained removals are mildly suspicious


def score_change(change: dict) -> int:
    score = 0
    flags = change.get("flags", [])

    if not flags:
        if change["change_type"] == "removed":
            score += BASE_REMOVED_WEIGHT
        else:
            score += BASE_MODIFIED_WEIGHT
        return score

    for flag in flags:
        matched = False
        for key, weight in FLAG_WEIGHTS.items():
            if flag.startswith(key):
                score += weight
                matched = True
                break
        if not matched and flag.startswith("SUSPICIOUS_PATTERN"):
            score += DEFAULT_SUSPICIOUS_PATTERN_WEIGHT

    return min(score, 100)  # cap per-change score at 100


def severity_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def score_all(changes: list) -> dict:
    """
    Attaches a numeric score + severity label to each change, and
    returns an overall summary dict too.
    """
    scored = []
    for c in changes:
        s = score_change(c)
        c["risk_score"] = s
        c["severity"] = severity_label(s)
        scored.append(c)

    overall = max((c["risk_score"] for c in scored), default=0)
    counts = {}
    for c in scored:
        counts[c["severity"]] = counts.get(c["severity"], 0) + 1

    return {
        "changes": scored,
        "overall_score": overall,
        "overall_severity": severity_label(overall),
        "counts_by_severity": counts,
        "total_changes": len(scored),
    }
