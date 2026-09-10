import json
import os
from datetime import datetime


def build_recommended_actions(incident):
    recommendations = []

    mitre_ids = {
        technique["mitre_id"]
        for technique in incident.get("mitre_summary", [])
    }

    if "T1059.001" in mitre_ids:
        recommendations.append(
            "Review the PowerShell command line and determine "
            "whether the execution was authorized."
        )

    if "T1204.002" in mitre_ids:
        recommendations.append(
            "Investigate the executable launched from the user-writable "
            "directory and verify its origin and integrity."
        )

    if "T1547.001" in mitre_ids:
        recommendations.append(
            "Review the affected Registry Run/RunOnce key and verify "
            "whether the persistence entry is legitimate."
        )

    if incident.get("severity") == "CRITICAL":
        recommendations.append(
            "Prioritize the incident for immediate analyst investigation "
            "and consider isolating the affected endpoint."
        )

    return recommendations


def build_incident_summary(incident):
    return (
        f"{incident['alert_count']} security alerts were correlated on "
        f"{incident['host']} for user {incident['user']} within the "
        f"configured correlation window. The incident received a risk "
        f"score of {incident['risk_score']}/100 and was classified as "
        f"{incident['severity']}."
    )


def build_report(incident):
    return {
        "report_metadata": {
            "tool": "ThreatHunter",
            "report_type": "SOC Incident Report",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "incident": {
            "incident_id": incident["incident_id"],
            "severity": incident["severity"],
            "risk_score": incident["risk_score"],
            "host": incident["host"],
            "user": incident["user"],
            "start_time": incident["start_time"],
            "end_time": incident["end_time"],
            "alert_count": incident["alert_count"],
            "unique_event_count": incident["event_count"],
            "event_ids": incident["event_ids"],
        },
        "summary": build_incident_summary(incident),
        "mitre_techniques": incident["mitre_summary"],
        "timeline": incident["timeline"],
        "recommended_actions": build_recommended_actions(incident),
        "alerts": incident["alerts"],
    }


def save_incident_report(incident, output_directory="reports"):
    os.makedirs(output_directory, exist_ok=True)

    report = build_report(incident)

    incident_id = incident["incident_id"]
    file_name = f"{incident_id}.json"

    file_path = os.path.join(
        output_directory,
        file_name,
    )

    with open(
        file_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return file_path