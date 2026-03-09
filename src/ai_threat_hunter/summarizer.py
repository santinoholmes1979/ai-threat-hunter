from __future__ import annotations

import pandas as pd


def build_summary(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return (
            "No high-confidence suspicious activity was identified in the current dataset. "
            "Continue hunting for encoded PowerShell, authentication abuse, persistence changes, "
            "and abnormal parent-child process relationships."
        )

    top_rules = alerts["rule_name"].value_counts().to_dict()
    top_hosts = alerts["host"].fillna("unknown").replace("", "unknown").value_counts().head(3).to_dict()
    top_sources = alerts["source_ip"].fillna("unknown").replace("", "unknown").value_counts().head(3).to_dict()

    return (
        f"Threat hunting identified {len(alerts)} findings. "
        f"Most common detections: {top_rules}. "
        f"Most affected hosts: {top_hosts}. "
        f"Most notable source IPs: {top_sources}. "
        "Recommended next actions: validate PowerShell command intent, review authentication logs for account lockout risk, "
        "inspect registry persistence artifacts, and pivot into related host and user activity."
    )