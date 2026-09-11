# Credential Theft Investigation Lab

A defensive Detection Engineering and Incident Response project for correlating identity and endpoint telemetry that may be associated with credential theft or misuse.

This repository is intentionally **investigation-focused and safe**. It does not contain credential-dumping code, phishing infrastructure, token theft, password extraction, malware, exploit payloads, or live targeting. All data is synthetic.

## Why this project exists

Identity incidents are rarely proven by one alert. Analysts typically need to correlate authentication failures, successful logons, MFA changes, password-reset activity, privileged-account context, endpoint credential-access telemetry, device context, and session anomalies before deciding whether containment or credential rotation is justified.

This project demonstrates that workflow as a small, auditable Python investigation pipeline.

## Capabilities

- Immutable, validated identity-event and finding models
- Strict UTC timestamp handling
- Duplicate evidence-ID rejection and fail-closed JSON ingestion
- Credential-access telemetry triage
- Suspicious authentication-sequence correlation
- MFA-change and password-reset context
- New-device and impossible-travel context
- Privileged-identity risk weighting
- Session/token anomaly investigation
- Deterministic finding IDs
- Explainable 0–100 risk scoring
- Severity and confidence kept separate
- Evidence preservation
- ATT&CK contextual mappings
- Remediation and revalidation guidance
- Executive metrics and Markdown reporting
- Offline CLI workflow
- Synthetic investigation dataset
- Unit tests and GitHub Actions CI

## Architecture

```text
Synthetic identity / endpoint events
            |
            v
      Schema validation
            |
            v
    Canonical event model
            |
            v
   Correlation + risk engine
            |
      +-----+-----+
      |           |
      v           v
 Evidence     ATT&CK context
 preservation
      |           |
      +-----+-----+
            v
      Prioritized findings
            |
            v
 Executive + technical report
            |
            v
 Remediation / validation workflow
```

## Repository structure

```text
.github/workflows/ci.yml          Least-privilege CI
src/models.py                    Immutable models and validation
src/io.py                        Fail-closed JSON ingestion
src/investigation.py             Correlation and risk engine
src/reporting.py                 Metrics and Markdown reporting
src/cli.py                       Offline command-line interface
data/synthetic_identity_events.json
                                Synthetic identity telemetry
tests/test_investigation.py      Unit tests
docs/architecture-methodology.md Architecture and methodology
reports/example-assessment.md    Example executive investigation
```

## Investigation analytics

### 1. Credential-access telemetry
Security-product telemetry associated with credential access is prioritized for analyst review. Privileged identity context raises impact. The finding explicitly states that telemetry is **not proof that credentials were successfully stolen**.

### 2. Suspicious authentication sequence
A successful sign-in is correlated with events in the preceding 30 minutes. The engine looks for combinations of:

- repeated authentication failures
- recent password reset
- recent MFA change
- new-device context
- impossible-travel context
- privileged identity usage

The engine requires multiple signals before raising the sequence as a finding.

### 3. Session/token anomaly
An anomalous identity-provider session or token event is converted into a defensive investigation finding. The project never attempts to steal, replay, or decode a real token.

## Risk model

Scores are bounded from **0–100** and are designed for prioritization rather than mathematical proof of compromise.

Example factors include:

- source telemetry risk
- number of correlated identity signals
- privileged-account context
- impossible-travel context
- new-device context
- credential-access telemetry

Severity bands:

| Score | Severity |
|---:|---|
| 85–100 | Critical |
| 65–84 | High |
| 40–64 | Medium |
| 0–39 | Low |

Confidence is reported separately from severity so that high potential impact does not automatically imply high evidentiary certainty.

## MITRE ATT&CK context

The project uses ATT&CK for investigation context:

- **T1003 — OS Credential Dumping**
- **T1078 — Valid Accounts**
- **T1110 — Brute Force**
- **T1539 — Steal Web Session Cookie**

These mappings describe behaviors relevant to triage. They do not assert that an adversary successfully executed a technique.

## Running the lab

Requires Python 3.12+.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_identity_events.json --output reports/generated-assessment.md
```

The CLI operates only on the supplied local JSON file and writes a Markdown report.

## Synthetic scenario

The included dataset contains clearly fictional identities under the `.test` namespace and documentation-only IP ranges. It demonstrates:

- repeated failed sign-ins
- an MFA change
- a successful sign-in from a new device with impossible-travel context
- a privileged credential-access alert
- a separate session/token anomaly
- a benign sign-in that should not generate a finding

No real organization, client, employee, credential, or production telemetry is represented.

## Testing strategy

The unit tests cover:

1. invalid risk rejection
2. unsupported event-type rejection
3. severity thresholds
4. deterministic finding IDs
5. credential-access telemetry detection
6. multi-signal authentication correlation
7. token anomaly detection
8. benign authentication suppression
9. affected-user metrics
10. report validation content

CI compiles the Python source, runs the unit-test suite, and generates a report from the synthetic dataset.

## Investigation workflow

```text
Preserve evidence
      -> validate schema
      -> correlate identity signals
      -> prioritize findings
      -> validate user/device/source context
      -> contain when justified
      -> rotate credentials/revoke sessions through approved process
      -> revalidate telemetry
      -> close only with evidence
```

## Remediation philosophy

The project emphasizes evidence-backed closure. Alert disappearance by itself is not treated as remediation success. Depending on the investigation, validation can include:

- credential rotation completed through authorized identity procedures
- risky sessions invalidated
- MFA state verified
- endpoint telemetry reviewed and clean
- privileged access reviewed
- authentication behavior returned to expected patterns
- recurrence monitoring completed

## Skills demonstrated

- Detection Engineering
- Incident Response
- Identity Security
- Security Analytics
- Python security automation
- Event normalization
- Correlation logic
- Risk scoring
- Evidence preservation
- MITRE ATT&CK mapping
- Security reporting
- Remediation validation
- Defensive CI/CD practices

## Limitations

This is a deterministic synthetic lab, not an enterprise UEBA product. It does not connect to Microsoft Entra ID, Active Directory, CrowdStrike, Defender, SIEM platforms, threat-intelligence services, or live endpoints. Production investigations require organization-specific baselines, privacy controls, validated telemetry, change management, and analyst judgment.

## Roadmap

- Add configurable correlation windows and thresholds
- Add identity-risk baselining using synthetic historical data
- Add pluggable parsers for sanitized SIEM-export formats
- Add evidence-timeline rendering
- Add investigation state tracking and closure metrics
- Add Sigma/KQL examples for defensive detection parity

## Safety statement

This repository is for defensive security engineering, detection, investigation, and remediation validation. It contains no credential theft capability, no credential extraction, no password attacks, no malware, no persistence, no session hijacking, no exploit automation, no production targeting, and no confidential data.
