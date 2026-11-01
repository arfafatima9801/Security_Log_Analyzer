
# Security Log Analyzer

## 1. Project Overview

Security Log Analyzer is a Python-based tool that reads log
records, identifies potentially suspicious activity using
rule-based detection, generates evidence-backed alerts, and
saves the alerts for further review.

The project is developed by a team of two students as an
academic cybersecurity project.

## 2. Objectives

- Read log records from a documented CSV file.
- Identify malformed or invalid records safely.
- Normalize log events into a consistent structure.
- Implement at least four configurable detection rules.
- Generate alerts with severity, rule details, and evidence.
- Save generated alerts to an output file.
- Test the system using synthetic data.
- Report processing time and detection results.

## 3. Technology

- Python 3
- CSV and other Python standard-library modules
- Git and GitHub for version control
- pytest for automated testing

## 4. Project Structure

```text
Security_Log_Analyzer/
├── main.py
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── parser.py
│   ├── normalizer.py
│   ├── config.py
│   ├── rules.py
│   ├── alerts.py
│   └── storage.py
├── data/
│   ├── sample_logs.csv
│   └── expected_results.csv
├── tests/
│   ├── test_parser.py
│   ├── test_rules.py
│   └── test_integration.py
└── output/
```

## 5. Input Data

The primary input is a CSV file containing these fields:

- `timestamp`: date and time of the event
- `event_type`: type of event
- `username`: associated username
- `source_ip`: source IP address
- `message`: short event description

The dataset will contain synthetic normal and suspicious
events. It will not contain real users' private security logs.

## 6. Planned Detection Rules

- R1: Repeated failed logins within a time window.
- R2: Successful login after repeated failures.
- R3: Account creation or privilege-change events.
- R4: Unusually high event volume from a source IP.

Thresholds and time windows will be documented in
`src/config.py`.

## 7. Installation

Install Python 3 and open a terminal in the project folder.

Create and activate a virtual environment:

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install project dependencies:

```powershell
python -m pip install -r requirements.txt
```

## 8. Usage

After all project modules have been implemented, run:

```powershell
python main.py --input data/sample_logs.csv --output output/alerts.csv
```

The program is intended to report processed events,
invalid records, alerts by rule and severity, and processing
time.

## 9. Testing

Run the automated tests with:

```powershell
python -m pytest
```

Tests will cover valid records, malformed input, detection
rules, integration, and repeatability.

## 10. Configuration

Detection thresholds and time windows will be maintained
in `src/config.py` so that the detection behaviour can be
reviewed and adjusted without hiding values inside rule code.

## 11. Output

Generated alerts will be saved under the `output/` folder.
Each alert should identify the rule, severity, affected
entity, timestamp, and evidence or reason.

## 12. Scope and Limitations

This project is an academic prototype that uses synthetic
data and rule-based detection. An alert indicates a pattern
that requires human review; it does not prove that an attack
occurred.

The tool does not automatically block accounts, collect
logs without permission, or claim enterprise-level
reliability.

Detection quality depends on the dataset, rule thresholds,
and event patterns represented in the input.

## 13. Team Contributions

The two team members will divide implementation, testing,
documentation, and integration tasks. Actual individual
contributions will be documented as the project progresses.

## 14. Project Status

Development is in progress. Features will be marked as
completed after implementation and testing.
```

