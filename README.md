\# AI Threat Hunter

## Dashboard Preview

![Main Dashboard](screenshots/main_dashboard.png)

## Alerts and Analyst Summary

![Alerts Table](screenshots/alerts_table_summary.png)

AI Threat Hunter is a Python and Streamlit cybersecurity portfolio project that simulates endpoint and authentication telemetry, normalizes event data, executes hunt-driven detection logic, and generates analyst-friendly findings.



\## Project Purpose



This project demonstrates how a threat hunter or SOC analyst can move from raw telemetry to actionable findings by combining:



\- synthetic event generation

\- log normalization

\- rule-based hunting logic

\- suspicious pattern detection

\- analyst-focused summaries

\- dashboard-based investigation



## Features

- Synthetic security log generation
- Event normalization pipeline
- Detection logic for:
  - Suspicious PowerShell (MITRE T1059.001)
  - Password spray detection (MITRE T1110.003)
  - Registry Run key persistence (MITRE T1547.001)
  - Office spawning shell execution (MITRE T1204)
- MITRE ATT&CK technique mapping for detections
- Natural-language hunt prompt matching
- AI-style analyst summary
- Streamlit dashboard for investigation


\## Project Structure



```text

ai-threat-hunter/

│   app.py

│   README.md

│   requirements.txt

│

├───data

├───docs

├───hunts

│       hunt\_prompts.yml

│

└───src

&nbsp;   └───ai\_threat\_hunter

&nbsp;       │   \_\_init\_\_.py

&nbsp;       │   config.py

&nbsp;       │   generator.py

&nbsp;       │   hunter.py

&nbsp;       │   normalizer.py

&nbsp;       │   summarizer.py

&nbsp;       │

&nbsp;       ├───detectors

&nbsp;       │       \_\_init\_\_.py

&nbsp;       │       rules.py

&nbsp;       │

&nbsp;       └───utils

&nbsp;               io.py

## Setup

From PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt


---

## Run the Project

```markdown
## Run the Project

Generate logs, normalize them, and launch the dashboard:

```powershell
python -m src.ai_threat_hunter.generator
python -m src.ai_threat_hunter.normalizer
streamlit run app.py


---

## Example Hunt Queries

```markdown
## Example Hunt Queries

Use hunt search terms like:

- powershell
- password spray
- registry persistence
- office spawned shell

## Why This Project Matters

This project demonstrates practical cybersecurity skills in:

- threat hunting
- detection logic development
- telemetry normalization
- suspicious behavior analysis
- investigation workflow design
- analyst-facing dashboard presentation

It demonstrates how security telemetry can be transformed into explainable findings that support real-world SOC investigations.

## MITRE ATT&CK Alignment

This project maps detections to MITRE ATT&CK techniques to demonstrate how security telemetry can be translated into standardized threat intelligence frameworks.

| Detection | MITRE Technique | Tactic |
|-----------|----------------|-------|
| Suspicious PowerShell | T1059.001 | Execution |
| Password Spray | T1110.003 | Credential Access |
| Run Key Persistence | T1547.001 | Persistence |
| Office Spawned Shell | T1204 | Execution |

This mapping helps analysts quickly understand attacker behavior and supports SOC investigation workflows.

