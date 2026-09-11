from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

ALLOWED_EVENT_TYPES = {
    "auth_failure",
    "auth_success",
    "mfa_change",
    "password_reset",
    "credential_access_alert",
    "privileged_role_change",
    "token_anomaly",
}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class IdentityEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    user: str
    source_ip: str
    device: str
    outcome: str
    risk: int
    privileged: bool = False
    new_device: bool = False
    impossible_travel: bool = False

    def __post_init__(self) -> None:
        if not self.event_id or not self.user:
            raise ValueError("event_id and user are required")
        if self.event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"unsupported event_type: {self.event_type}")
        if not 0 <= self.risk <= 100:
            raise ValueError("risk must be between 0 and 100")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")


@dataclass(frozen=True)
class InvestigationFinding:
    finding_id: str
    user: str
    title: str
    score: int
    severity: str
    confidence: str
    evidence_ids: Tuple[str, ...]
    attack_techniques: Tuple[str, ...]
    rationale: str
    remediation: str
    validation: str

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")
        if self.severity not in {"Low", "Medium", "High", "Critical"}:
            raise ValueError("invalid severity")
        if self.confidence not in {"Low", "Medium", "High"}:
            raise ValueError("invalid confidence")
        if not self.evidence_ids:
            raise ValueError("at least one evidence id is required")
