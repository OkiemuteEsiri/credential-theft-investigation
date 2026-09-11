# Architecture and Investigation Methodology

## Purpose

This project demonstrates a defensive identity-security investigation workflow for reviewing telemetry that may be associated with credential theft or misuse. It is designed for synthetic/offline analysis and deliberately avoids credential extraction, account takeover, phishing infrastructure, malware, token theft, or production targeting.

## Architecture

1. **Input validation** — `src/io.py` loads synthetic JSON events, rejects malformed records, duplicate evidence IDs, and unsupported event types.
2. **Canonical event model** — `src/models.py` defines immutable identity events and investigation findings with bounded risk scores and evidence requirements.
3. **Correlation engine** — `src/investigation.py` groups evidence by identity and detects investigation patterns such as credential-access telemetry, suspicious authentication sequences, and token/session anomalies.
4. **Risk prioritization** — findings receive explainable 0–100 scores based on signal severity, identity privilege, authentication context, and correlated evidence.
5. **Reporting** — `src/reporting.py` produces executive metrics and detailed Markdown findings with evidence, ATT&CK context, remediation, and revalidation criteria.
6. **CLI** — `src/cli.py` provides an offline workflow from JSON evidence to a generated investigation report.

## Detection methodology

### Credential-access telemetry
A security product alert associated with credential-access behavior is elevated for analyst review. Privileged identity context increases priority. The signal is never treated as proof that a secret or password was successfully obtained.

### Suspicious authentication sequence
A successful sign-in is correlated with preceding events in a 30-minute window. The engine raises priority only when multiple contextual signals exist, such as repeated failures, an MFA change, password-reset activity, a new device, impossible-travel context, or privileged identity usage.

### Session/token anomaly
An identity-provider session or token anomaly is converted into an investigation finding with explicit session review and revocation guidance. The project does not attempt to acquire, replay, or decode real session tokens.

## ATT&CK context

- **T1003 — OS Credential Dumping**: contextual mapping for credential-access telemetry.
- **T1078 — Valid Accounts**: contextual mapping for suspicious successful authentication.
- **T1110 — Brute Force**: contextual mapping where repeated failed sign-ins precede a successful sign-in.
- **T1539 — Steal Web Session Cookie**: contextual mapping for anomalous session/token evidence.

ATT&CK mappings describe possible adversary behavior relevant to analyst triage. They are not evidence that a technique was successfully executed.

## Investigation workflow

1. Preserve original event IDs and timestamps.
2. Validate event schema and reject malformed records.
3. Correlate signals by identity and time window.
4. Prioritize findings by score, severity, and privilege context.
5. Validate user, device, source, authentication method, and identity-provider telemetry.
6. Apply approved containment actions when compromise is sufficiently supported.
7. Rotate credentials or revoke sessions only through authorized incident-response procedures.
8. Revalidate authentication telemetry and endpoint posture before closure.

## Remediation and closure criteria

A finding should not be closed merely because an alert stopped firing. Closure should require evidence appropriate to the scenario, such as successful credential rotation, revoked risky sessions, restored MFA state, clean endpoint telemetry, expected authentication behavior, and completion of required identity-control improvements.

## Limitations

This project uses deterministic rules and synthetic data. It does not perform behavioral baselining, UEBA, threat-intelligence lookups, malware analysis, memory inspection, credential extraction, live API calls, or identity-provider enforcement. Production investigations require validated telemetry, organization-specific policies, legal/privacy controls, and analyst judgment.
