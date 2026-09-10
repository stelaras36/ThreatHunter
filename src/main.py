from loader import load_events
from detector import run_detections
from correlator import correlate_alerts
from reporter import save_incident_report


def main():
    try:
        events = load_events("data/sample_events.json")

    except (FileNotFoundError, ValueError) as error:
        print("[ERROR]")
        print(error)
        return

    print("ThreatHunter started successfully.")
    print(f"Loaded {len(events)} events.\n")

    all_alerts = []

    for event in events:
        alerts = run_detections(event)
        all_alerts.extend(alerts)

    for alert in all_alerts:
        print("[ALERT]")
        print(f"Event ID: {alert['event_id']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Host: {alert['host']}")
        print(f"User: {alert['user']}")
        print(f"Title: {alert['title']}")
        print(f"Severity: {alert['severity']}")
        print(
            f"MITRE ATT&CK: "
            f"{alert['mitre_id']} - {alert['mitre_technique']}"
        )
        print()

    print(f"Total alerts detected: {len(all_alerts)}")
    print()

    incidents = correlate_alerts(all_alerts)

    print(f"Total incidents created: {len(incidents)}")
    print()

    for incident in incidents:
        print("=" * 60)
        print(f"INCIDENT: {incident['incident_id']}")
        print("=" * 60)
        print(f"Host: {incident['host']}")
        print(f"User: {incident['user']}")
        print(f"Start Time: {incident['start_time']}")
        print(f"End Time: {incident['end_time']}")
        print(f"Alerts: {incident['alert_count']}")
        print(f"Unique Events: {incident['event_count']}")
        print(f"Risk Score: {incident['risk_score']}/100")
        print(f"Severity: {incident['severity']}")
        print()

        print("Event IDs:")
        for event_id in incident["event_ids"]:
            print(f"  - {event_id}")

        print()

        print("Correlated Alerts:")
        for alert in incident["alerts"]:
            print(
                f"  [{alert['severity']}] "
                f"{alert['event_id']} - {alert['title']}"
            )

        print()
        print("MITRE ATT&CK SUMMARY:")
        print("-" * 60)

        for technique in incident["mitre_summary"]:
            print(
                f"  {technique['mitre_id']} - "
                f"{technique['mitre_technique']}"
            )

        print()
        print("ATTACK TIMELINE:")
        print("-" * 60)

        for entry in incident["timeline"]:
            print(
                f"{entry['timestamp']} | "
                f"{entry['event_id']} | "
                f"[{entry['severity']}] "
                f"{entry['title']}"
            )
            print(
                f"    MITRE ATT&CK: "
                f"{entry['mitre_id']} - {entry['mitre_technique']}"
            )

        print("=" * 60)

        report_path = save_incident_report(incident)

        print()
        print(f"Incident report saved: {report_path}")
        print()


if __name__ == "__main__":
    main()