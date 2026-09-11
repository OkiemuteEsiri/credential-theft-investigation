from collections import Counter
from typing import Iterable

from .models import InvestigationFinding


def metrics(findings: Iterable[InvestigationFinding]) -> dict:
    items = list(findings)
    by_severity = Counter(f.severity for f in items)
    return {
        "total_findings": len(items),
        "critical_high": by_severity["Critical"] + by_severity["High"],
        "highest_score": max((f.score for f in items), default=0),
        "affected_users": len({f.user for f in items}),
        "by_severity": dict(by_severity),
    }


def render_markdown(findings: Iterable[InvestigationFinding]) -> str:
    items = list(findings)
    m = metrics(items)
    lines = [
        "# Credential Theft Investigation Report",
        "",
        "> Synthetic defensive assessment. Findings are investigation signals, not proof of compromise.",
        "",
        "## Executive metrics",
        f"- Total findings: {m['total_findings']}",
        f"- Critical / High: {m['critical_high']}",
        f"- Affected users: {m['affected_users']}",
        f"- Highest risk score: {m['highest_score']}",
        "",
        "## Prioritized findings",
    ]
    for f in items:
        lines.extend([
            "",
            f"### {f.severity}: {f.title} — {f.user}",
            f"- Risk score: {f.score}/100",
            f"- Confidence: {f.confidence}",
            f"- Evidence: {', '.join(f.evidence_ids)}",
            f"- ATT&CK context: {', '.join(f.attack_techniques)}",
            f"- Rationale: {f.rationale}",
            f"- Remediation: {f.remediation}",
            f"- Validation: {f.validation}",
        ])
    return "\n".join(lines) + "\n"
