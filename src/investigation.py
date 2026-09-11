import hashlib
from collections import defaultdict
from datetime import timedelta
from typing import Iterable, List

from .models import IdentityEvent, InvestigationFinding


def severity(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def finding_id(user: str, title: str, evidence_ids: Iterable[str]) -> str:
    seed = "|".join([user, title, *sorted(evidence_ids)])
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def investigate(events: Iterable[IdentityEvent]) -> List[InvestigationFinding]:
    by_user = defaultdict(list)
    for event in events:
        by_user[event.user].append(event)

    findings: List[InvestigationFinding] = []
    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: e.timestamp)

        alerts = [e for e in user_events if e.event_type == "credential_access_alert"]
        if alerts:
            evidence = tuple(e.event_id for e in alerts)
            base = max(e.risk for e in alerts)
            bonus = 10 if any(e.privileged for e in alerts) else 0
            score = min(100, base + bonus)
            findings.append(InvestigationFinding(
                finding_id(user, "Credential-access telemetry requires investigation", evidence),
                user,
                "Credential-access telemetry requires investigation",
                score,
                severity(score),
                "High",
                evidence,
                ("T1003",),
                "Endpoint or identity telemetry reported behavior associated with credential access. This is an investigation signal, not proof that credentials were stolen.",
                "Isolate affected endpoints when warranted, rotate impacted credentials through approved identity procedures, and review privileged access.",
                "Confirm endpoint telemetry is clean, credentials have been rotated where required, and follow-up authentication shows no recurrence.",
            ))

        for idx, event in enumerate(user_events):
            if event.event_type != "auth_success":
                continue
            window_start = event.timestamp - timedelta(minutes=30)
            preceding = [e for e in user_events[:idx] if window_start <= e.timestamp <= event.timestamp]
            failed = [e for e in preceding if e.event_type == "auth_failure"]
            reset = [e for e in preceding if e.event_type == "password_reset"]
            mfa = [e for e in preceding if e.event_type == "mfa_change"]
            signals = sum([
                bool(failed and len(failed) >= 3),
                bool(reset),
                bool(mfa),
                event.new_device,
                event.impossible_travel,
                event.privileged,
            ])
            if signals >= 2:
                evidence_events = failed[-3:] + reset[-1:] + mfa[-1:] + [event]
                evidence = tuple(dict.fromkeys(e.event_id for e in evidence_events))
                score = min(100, 35 + signals * 10 + event.risk // 4)
                findings.append(InvestigationFinding(
                    finding_id(user, "Suspicious authentication sequence", evidence),
                    user,
                    "Suspicious authentication sequence",
                    score,
                    severity(score),
                    "Medium" if signals < 4 else "High",
                    evidence,
                    ("T1078", "T1110"),
                    "A successful sign-in followed multiple identity-risk indicators within a short window. Correlation raises investigation priority but does not establish credential theft.",
                    "Validate the user and device, revoke risky sessions if approved, reset credentials where compromise is suspected, and review identity-provider controls.",
                    "Verify subsequent sign-ins originate from expected devices/locations and that risky-session and credential-reset actions completed successfully.",
                ))

        token_events = [e for e in user_events if e.event_type == "token_anomaly"]
        for token in token_events:
            score = min(100, 50 + token.risk // 2 + (10 if token.privileged else 0))
            findings.append(InvestigationFinding(
                finding_id(user, "Session or token anomaly", (token.event_id,)),
                user,
                "Session or token anomaly",
                score,
                severity(score),
                "Medium",
                (token.event_id,),
                ("T1539", "T1078"),
                "Identity telemetry identified an anomalous session or token condition requiring analyst validation.",
                "Review session history and identity-provider logs; revoke anomalous sessions under the incident-response process when justified.",
                "Confirm anomalous sessions are invalidated and no equivalent telemetry recurs during the validation period.",
            ))

    return sorted(findings, key=lambda f: (-f.score, f.user, f.finding_id))
