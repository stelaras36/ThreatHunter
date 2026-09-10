SEVERITY_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 25,
    "CRITICAL": 40,
}


def calculate_risk_score(alerts):
    score = 0

    for alert in alerts:
        severity = alert.get("severity", "LOW").upper()
        score += SEVERITY_WEIGHTS.get(severity, 0)

    return min(score, 100)


def get_incident_severity(score):
    if score >= 80:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"