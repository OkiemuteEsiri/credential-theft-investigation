import unittest
from datetime import datetime, timezone

from src.investigation import finding_id, investigate, severity
from src.models import IdentityEvent
from src.reporting import metrics, render_markdown


def ev(event_id, minute, event_type, user="u@example.test", risk=50, **kwargs):
    return IdentityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 9, 10, 9, minute, tzinfo=timezone.utc),
        event_type=event_type,
        user=user,
        source_ip="192.0.2.1",
        device="SYN-01",
        outcome="success" if "success" in event_type else "alert",
        risk=risk,
        **kwargs,
    )


class InvestigationTests(unittest.TestCase):
    def test_invalid_risk_rejected(self):
        with self.assertRaises(ValueError):
            ev("x", 0, "auth_success", risk=101)

    def test_unknown_type_rejected(self):
        with self.assertRaises(ValueError):
            ev("x", 0, "unknown")

    def test_severity_boundaries(self):
        self.assertEqual(severity(85), "Critical")
        self.assertEqual(severity(65), "High")
        self.assertEqual(severity(40), "Medium")
        self.assertEqual(severity(10), "Low")

    def test_finding_id_is_deterministic(self):
        a = finding_id("u", "x", ["b", "a"])
        b = finding_id("u", "x", ["a", "b"])
        self.assertEqual(a, b)

    def test_credential_access_signal_detected(self):
        findings = investigate([ev("a", 0, "credential_access_alert", risk=80)])
        self.assertEqual(len(findings), 1)
        self.assertIn("T1003", findings[0].attack_techniques)

    def test_auth_sequence_requires_multiple_signals(self):
        findings = investigate([
            ev("f1", 0, "auth_failure"),
            ev("f2", 2, "auth_failure"),
            ev("f3", 4, "auth_failure"),
            ev("s1", 8, "auth_success", new_device=True, risk=70),
        ])
        self.assertTrue(any(f.title == "Suspicious authentication sequence" for f in findings))

    def test_token_anomaly_detected(self):
        findings = investigate([ev("t1", 0, "token_anomaly", risk=60)])
        self.assertEqual(findings[0].title, "Session or token anomaly")

    def test_benign_success_does_not_alert(self):
        self.assertEqual(investigate([ev("s", 0, "auth_success", risk=10)]), [])

    def test_metrics_count_users(self):
        findings = investigate([
            ev("a", 0, "credential_access_alert", user="a@example.test"),
            ev("b", 1, "token_anomaly", user="b@example.test"),
        ])
        self.assertEqual(metrics(findings)["affected_users"], 2)

    def test_report_contains_validation(self):
        findings = investigate([ev("a", 0, "credential_access_alert")])
        report = render_markdown(findings)
        self.assertIn("Validation:", report)
        self.assertIn("not proof of compromise", report)


if __name__ == "__main__":
    unittest.main()
