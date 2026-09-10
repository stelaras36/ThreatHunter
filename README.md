# ThreatHunter

ThreatHunter is a Python-based SOC detection and incident investigation project designed to analyze endpoint security events, generate alerts, correlate suspicious activity, calculate incident risk, map detections to MITRE ATT&CK, and produce structured incident reports.

The project is designed as a safe portfolio lab and operates on synthetic security event datasets. It does not require live endpoint monitoring, malware execution, drivers, or changes to the host operating system.

## Features

- JSON security event ingestion
- Modular Python detection engine
- Multiple detection rules
- Alert severity classification
- MITRE ATT&CK mapping
- Host and user based event correlation
- Configurable correlation time window
- Incident creation
- Risk scoring from 0 to 100
- Incident severity classification
- Attack timeline generation
- MITRE ATT&CK incident summary
- Recommended analyst actions
- JSON SOC incident reports
- Error handling for missing or invalid datasets
- Automated unit tests

## Detection Rules

ThreatHunter v1 includes detections for:

- Encoded PowerShell execution
- Microsoft Office applications spawning PowerShell
- Executables launched from user-writable directories
- PowerShell network connections
- Registry Run / RunOnce persistence

The detection engine treats individual signals as indicators for investigation rather than automatic proof of compromise.

## MITRE ATT&CK

Current detections include mappings such as:

- `T1059.001` - PowerShell
- `T1204.002` - Malicious File
- `T1547.001` - Registry Run Keys / Startup Folder

MITRE ATT&CK mappings are included to provide additional investigation context for detected activity.

## Detection and Investigation Pipeline

```text
Security Events
      |
      v
   loader.py
      |
      v
Detection Engine
      |
      v
    Alerts
      |
      v
  Correlation
      |
      v
   Incident
      |
      +----> Risk Score
      |
      +----> MITRE ATT&CK Summary
      |
      +----> Attack Timeline
      |
      +----> Recommended Actions
      |
      v
JSON Incident Report
```

## Project Structure

```text
ThreatHunter/
|
|-- data/
|   `-- sample_events.json
|
|-- reports/
|
|-- rules/
|
|-- src/
|   |-- correlator.py
|   |-- detector.py
|   |-- loader.py
|   |-- main.py
|   |-- mitre.py
|   |-- reporter.py
|   |-- scorer.py
|   `-- timeline.py
|
|-- tests/
|   |-- test_correlation.py
|   `-- test_detector.py
|
|-- .gitignore
|-- README.md
`-- requirements.txt
```

## Sample Attack Scenario

The included synthetic dataset contains both normal and suspicious activity.

ThreatHunter identifies a sequence similar to:

```text
Microsoft Word
      |
      v
Encoded PowerShell
      |
      v
Executable launched from Temp
      |
      v
PowerShell network connection
      |
      v
Registry persistence
```

Individual alerts are correlated when they occur for the same host and user within the configured time window.

## Example Incident

```text
INCIDENT: INC-0001

Host: WORKSTATION-01
User: stelios

Alerts: 5
Unique Events: 4

Risk Score: 80/100
Severity: CRITICAL
```

### MITRE ATT&CK Summary

```text
T1059.001 - PowerShell
T1204.002 - Malicious File
T1547.001 - Registry Run Keys / Startup Folder
```

### Attack Timeline

```text
09:15:21  Suspicious Encoded PowerShell
09:15:21  Office Application Spawned PowerShell
09:15:25  Executable Launched from User-Writable Directory
09:15:31  PowerShell Initiated Network Connection
09:16:02  Registry Run Key Persistence Detected
```

## Risk Scoring

ThreatHunter v1 uses the following internal scoring model:

```text
LOW       = 5 points
MEDIUM    = 10 points
HIGH      = 25 points
CRITICAL  = 40 points
```

Incident severity is calculated from the final score:

```text
0-24      LOW
25-49     MEDIUM
50-79     HIGH
80-100    CRITICAL
```

The score is capped at 100.

This is an internal project scoring model and is not intended to represent an industry-standard risk scoring framework.

## Requirements

- Python 3.12 or newer
- No external Python packages are required for v1

## Setup

Clone or download the project and open a terminal inside the project directory.

Create a virtual environment:

```bash
python -m venv .venv
```

On Windows, activate it with:

```bash
.venv\Scripts\activate
```

## Running ThreatHunter

From the root project directory:

```bash
python src\main.py
```

ThreatHunter will:

1. Load the security event dataset.
2. Execute all detection rules.
3. Generate alerts.
4. Correlate related alerts.
5. Calculate incident risk.
6. Generate the attack timeline.
7. Create a structured SOC incident report.

Generated reports are stored in:

```text
reports/
```

Example:

```text
reports/INC-0001.json
```

## Running Tests

Run all automated tests with:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

The test suite validates detection logic, false-positive handling, correlation behavior, time-window logic, and risk scoring.

## Safety

ThreatHunter v1 analyzes synthetic security telemetry only.

It does not:

- execute malware
- exploit systems
- install monitoring drivers
- modify Windows security settings
- perform live endpoint surveillance

This makes the project suitable for development and demonstration on a normal development environment.

## Future Development

Possible future versions may include:

- external YAML detection rules
- Sigma-style rule support
- additional Windows event types
- larger attack datasets
- advanced multi-stage attack correlation
- IOC extraction
- KQL detection equivalents
- CSV reporting
- SQLite incident storage
- interactive SOC dashboard

## Purpose

ThreatHunter was developed as a cybersecurity portfolio project focused on SOC analysis, detection engineering, incident correlation, threat investigation, and MITRE ATT&CK concepts.

## License

This project is intended for educational, defensive cybersecurity, and portfolio purposes.