import json
from pathlib import Path
from typing import List

from .models import IdentityEvent, parse_utc

REQUIRED_FIELDS = {
    "event_id", "timestamp", "event_type", "user", "source_ip", "device", "outcome", "risk"
}


def load_events(path: str) -> List[IdentityEvent]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("input must be a JSON array")

    events = []
    seen = set()
    for index, row in enumerate(payload):
        if not isinstance(row, dict):
            raise ValueError(f"row {index} must be an object")
        missing = REQUIRED_FIELDS - row.keys()
        if missing:
            raise ValueError(f"row {index} missing fields: {sorted(missing)}")
        if row["event_id"] in seen:
            raise ValueError(f"duplicate event_id: {row['event_id']}")
        seen.add(row["event_id"])
        events.append(IdentityEvent(
            event_id=str(row["event_id"]),
            timestamp=parse_utc(str(row["timestamp"])),
            event_type=str(row["event_type"]),
            user=str(row["user"]),
            source_ip=str(row["source_ip"]),
            device=str(row["device"]),
            outcome=str(row["outcome"]),
            risk=int(row["risk"]),
            privileged=bool(row.get("privileged", False)),
            new_device=bool(row.get("new_device", False)),
            impossible_travel=bool(row.get("impossible_travel", False)),
        ))
    return events
