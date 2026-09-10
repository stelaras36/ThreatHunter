import os
import sys
import unittest


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SRC_PATH = os.path.join(PROJECT_ROOT, "src")

if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)


from correlator import correlate_alerts
from scorer import calculate_risk_score, get_incident_severity


class TestCorrelation(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {
                "event_id": "TEST-0001",
                "timestamp": "2026-09-10T10:00:00",
                "host": "WORKSTATION-TEST",
                "user": "testuser",
                "title": "Suspicious Encoded PowerShell",
                "severity": "HIGH",
                "mitre_id": "T1059.001",
                "mitre_technique": "PowerShell",
            },
            {
                "event_id": "TEST-0002",
                "timestamp": "2026-09-10T10:01:00",
                "host": "WORKSTATION-TEST",
                "user": "testuser",
                "title": "Executable Launched from Temp",
                "severity": "MEDIUM",
                "mitre_id": "T1204.002",
                "mitre_technique": "Malicious File",
            },
            {
                "event_id": "TEST-0003",
                "timestamp": "2026-09-10T10:02:00",
                "host": "WORKSTATION-TEST",
                "user": "testuser",
                "title": "Registry Run Key Persistence",
                "severity": "MEDIUM",
                "mitre_id": "T1547.001",
                "mitre_technique": "Registry Run Keys / Startup Folder",
            },
        ]

    def test_alerts_create_incident(self):
        incidents = correlate_alerts(self.alerts)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0]["incident_id"],
            "INC-0001",
        )
        self.assertEqual(
            incidents[0]["alert_count"],
            3,
        )

    def test_risk_score_is_calculated_correctly(self):
        score = calculate_risk_score(self.alerts)

        self.assertEqual(score, 45)
        self.assertEqual(
            get_incident_severity(score),
            "MEDIUM",
        )

    def test_alerts_outside_time_window_do_not_create_incident(self):
        alerts = [
            self.alerts[0],
            self.alerts[1],
            {
                "event_id": "TEST-0004",
                "timestamp": "2026-09-10T10:10:00",
                "host": "WORKSTATION-TEST",
                "user": "testuser",
                "title": "Late Alert",
                "severity": "MEDIUM",
                "mitre_id": "T1547.001",
                "mitre_technique": "Registry Run Keys / Startup Folder",
            },
        ]

        incidents = correlate_alerts(alerts)

        self.assertEqual(len(incidents), 0)


if __name__ == "__main__":
    unittest.main()