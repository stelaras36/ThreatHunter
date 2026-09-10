from datetime import datetime, timedelta

from scorer import calculate_risk_score, get_incident_severity
from timeline import build_attack_timeline
from mitre import build_mitre_summary


def create_incident(alerts, incident_number):
    event_ids = sorted(
        {alert["event_id"] for alert in alerts}
    )

    risk_score = calculate_risk_score(alerts)
    severity = get_incident_severity(risk_score)
    attack_timeline = build_attack_timeline(alerts)
    mitre_summary = build_mitre_summary(alerts)

    return {
        "incident_id": f"INC-{incident_number:04d}",
        "host": alerts[0]["host"],
        "user": alerts[0]["user"],
        "start_time": alerts[0]["timestamp"],
        "end_time": alerts[-1]["timestamp"],
        "alert_count": len(alerts),
        "event_count": len(event_ids),
        "event_ids": event_ids,
        "risk_score": risk_score,
        "severity": severity,
        "timeline": attack_timeline,
        "mitre_summary": mitre_summary,
        "alerts": alerts,
    }


def correlate_alerts(alerts, window_minutes=5):
    if not alerts:
        return []

    grouped_alerts = {}

    for alert in alerts:
        key = (
            alert.get("host"),
            alert.get("user"),
        )

        if key not in grouped_alerts:
            grouped_alerts[key] = []

        grouped_alerts[key].append(alert)

    incidents = []
    incident_number = 1
    time_window = timedelta(minutes=window_minutes)

    for group in grouped_alerts.values():
        group.sort(
            key=lambda alert: datetime.fromisoformat(
                alert["timestamp"]
            )
        )

        current_cluster = []
        cluster_start = None

        for alert in group:
            alert_time = datetime.fromisoformat(
                alert["timestamp"]
            )

            if not current_cluster:
                current_cluster.append(alert)
                cluster_start = alert_time
                continue

            if alert_time - cluster_start <= time_window:
                current_cluster.append(alert)

            else:
                if len(current_cluster) >= 3:
                    incidents.append(
                        create_incident(
                            current_cluster,
                            incident_number,
                        )
                    )
                    incident_number += 1

                current_cluster = [alert]
                cluster_start = alert_time

        if len(current_cluster) >= 3:
            incidents.append(
                create_incident(
                    current_cluster,
                    incident_number,
                )
            )

            incident_number += 1

    return incidents