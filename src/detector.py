def detect_encoded_powershell(event):
    if event.get("event_type") != "process_creation":
        return None

    process_name = event.get("process_name", "").lower()
    command_line = event.get("command_line", "").lower()

    if process_name == "powershell.exe" and (
        "-encodedcommand" in command_line
        or "-enc " in command_line
    ):
        return {
            "event_id": event.get("event_id"),
            "title": "Suspicious Encoded PowerShell",
            "severity": "HIGH",
            "mitre_id": "T1059.001",
            "mitre_technique": "PowerShell",
        }

    return None


def detect_office_spawning_powershell(event):
    if event.get("event_type") != "process_creation":
        return None

    process_name = event.get("process_name", "").lower()
    parent_process = event.get("parent_process", "").lower()

    office_processes = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
    }

    if (
        process_name == "powershell.exe"
        and parent_process in office_processes
    ):
        return {
            "event_id": event.get("event_id"),
            "title": "Office Application Spawned PowerShell",
            "severity": "HIGH",
            "mitre_id": "T1059.001",
            "mitre_technique": "PowerShell",
        }

    return None


def detect_execution_from_user_writable_directory(event):
    if event.get("event_type") != "process_creation":
        return None

    command_line = event.get("command_line", "").lower()

    suspicious_paths = (
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\temp\\",
    )

    if any(path in command_line for path in suspicious_paths):
        return {
            "event_id": event.get("event_id"),
            "title": "Executable Launched from User-Writable Directory",
            "severity": "MEDIUM",
            "mitre_id": "T1204.002",
            "mitre_technique": "Malicious File",
        }

    return None


def detect_powershell_network_connection(event):
    if event.get("event_type") != "network_connection":
        return None

    process_name = event.get("process_name", "").lower()
    destination_port = event.get("destination_port")

    monitored_ports = {
        80,
        443,
        8080,
        8443,
    }

    if (
        process_name == "powershell.exe"
        and destination_port in monitored_ports
    ):
        return {
            "event_id": event.get("event_id"),
            "title": "PowerShell Initiated Network Connection",
            "severity": "MEDIUM",
            "mitre_id": "T1059.001",
            "mitre_technique": "PowerShell",
        }

    return None


def detect_registry_run_key_persistence(event):
    if event.get("event_type") != "registry_modification":
        return None

    registry_key = event.get("registry_key", "").lower()

    persistence_keys = (
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
    )

    if any(key in registry_key for key in persistence_keys):
        return {
            "event_id": event.get("event_id"),
            "title": "Registry Run Key Persistence Detected",
            "severity": "MEDIUM",
            "mitre_id": "T1547.001",
            "mitre_technique": "Registry Run Keys / Startup Folder",
        }

    return None


def run_detections(event):
    detection_rules = [
        detect_encoded_powershell,
        detect_office_spawning_powershell,
        detect_execution_from_user_writable_directory,
        detect_powershell_network_connection,
        detect_registry_run_key_persistence,
    ]

    alerts = []

    for rule in detection_rules:
        alert = rule(event)

        if alert:
            alert["timestamp"] = event.get("timestamp")
            alert["host"] = event.get("host")
            alert["user"] = event.get("user")
            alerts.append(alert)

    return alerts