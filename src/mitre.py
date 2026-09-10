def build_mitre_summary(alerts):
    techniques = {}

    for alert in alerts:
        mitre_id = alert.get("mitre_id")
        mitre_technique = alert.get("mitre_technique")

        if mitre_id and mitre_technique:
            techniques[mitre_id] = mitre_technique

    summary = []

    for mitre_id, technique in sorted(techniques.items()):
        summary.append(
            {
                "mitre_id": mitre_id,
                "mitre_technique": technique,
            }
        )

    return summary