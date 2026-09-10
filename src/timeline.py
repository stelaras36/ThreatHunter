from datetime import datetime


def build_attack_timeline(alerts):
    sorted_alerts = sorted(
        alerts,
        key=lambda alert: datetime.fromisoformat(
            alert["timestamp"]
        ),
    )

    timeline = []

    for alert in sorted_alerts:
        timeline_entry = {
            "timestamp": alert["timestamp"],
            "event_id": alert["event_id"],
            "title": alert["title"],
            "severity": alert["severity"],
            "mitre_id": alert["mitre_id"],
            "mitre_technique": alert["mitre_technique"],
        }

        timeline.append(timeline_entry)

    return timeline