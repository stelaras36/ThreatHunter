import os
import sys
import unittest


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SRC_PATH = os.path.join(PROJECT_ROOT, "src")

if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)


from detector import (
    detect_encoded_powershell,
    detect_execution_from_user_writable_directory,
)


class TestDetector(unittest.TestCase):

    def test_normal_powershell_does_not_trigger_encoded_detection(self):
        event = {
            "event_id": "TEST-0001",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe -NoProfile Get-Process",
        }

        alert = detect_encoded_powershell(event)

        self.assertIsNone(alert)

    def test_encoded_powershell_generates_high_alert(self):
        event = {
            "event_id": "TEST-0002",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "parent_process": "WINWORD.EXE",
            "command_line": (
                "powershell.exe -NoProfile "
                "-EncodedCommand TEST_DATA"
            ),
        }

        alert = detect_encoded_powershell(event)

        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["mitre_id"], "T1059.001")

    def test_execution_from_temp_generates_medium_alert(self):
        event = {
            "event_id": "TEST-0003",
            "event_type": "process_creation",
            "process_name": "update.exe",
            "parent_process": "powershell.exe",
            "command_line": (
                "C:\\Users\\test\\AppData\\Local\\Temp\\update.exe"
            ),
        }

        alert = detect_execution_from_user_writable_directory(event)

        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["mitre_id"], "T1204.002")


if __name__ == "__main__":
    unittest.main()