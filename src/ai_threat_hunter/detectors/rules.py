from __future__ import annotations

import pandas as pd


def detect_suspicious_powershell(df: pd.DataFrame) -> pd.DataFrame:
    mask = (
        (df["process_name"].str.contains("powershell", na=False)) |
        (df["command_line"].str.contains("powershell", case=False, na=False))
    ) & (
        df["command_line"].str.contains("encodedcommand|-enc|-nop|hidden|frombase64string|bypass", case=False, na=False)
    )

    alerts = df[mask].copy()
    alerts["rule_name"] = "SuspiciousPowerShell"
    alerts["severity"] = "high"
    alerts["confidence"] = 85
    alerts["reason"] = "PowerShell execution includes encoded, hidden, or defense-evasion style arguments."
    return alerts


def detect_runkey_persistence(df: pd.DataFrame) -> pd.DataFrame:
    mask = (
        (df["event_type"] == "registry_change") |
        (df["command_line"].str.contains("currentversion\\\\run", case=False, na=False)) |
        (df["registry_path"].str.contains("currentversion\\\\run", case=False, na=False))
    )

    alerts = df[mask].copy()
    alerts["rule_name"] = "RunKeyPersistence"
    alerts["severity"] = "high"
    alerts["confidence"] = 90
    alerts["reason"] = "Registry Run key modification may indicate persistence."
    return alerts


def detect_office_spawned_shell(df: pd.DataFrame) -> pd.DataFrame:
    mask = (
        df["parent_process"].str.contains("winword.exe|excel.exe|outlook.exe", case=False, na=False)
        &
        df["process_name"].str.contains("powershell.exe|cmd.exe", case=False, na=False)
    )

    alerts = df[mask].copy()
    alerts["rule_name"] = "OfficeSpawnedShell"
    alerts["severity"] = "high"
    alerts["confidence"] = 88
    alerts["reason"] = "Office application spawned a shell or PowerShell process."
    return alerts


def detect_password_spray(df: pd.DataFrame) -> pd.DataFrame:
    failures = df[df["event_type"] == "auth_failure"].copy()
    if failures.empty:
        return pd.DataFrame()

    grouped = (
        failures.groupby("source_ip")
        .agg(
            failed_attempts=("target_user", "count"),
            unique_users=("target_user", "nunique"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )

    grouped = grouped[(grouped["failed_attempts"] >= 5) & (grouped["unique_users"] >= 5)]
    if grouped.empty:
        return pd.DataFrame()

    alerts = grouped.copy()
    alerts["timestamp"] = alerts["first_seen"]
    alerts["event_type"] = "auth_failure_pattern"
    alerts["user"] = "multiple"
    alerts["host"] = "multiple"
    alerts["parent_process"] = ""
    alerts["process_name"] = ""
    alerts["command_line"] = ""
    alerts["target_user"] = "multiple"
    alerts["registry_path"] = ""
    alerts["destination_ip"] = ""
    alerts["destination_port"] = ""
    alerts["status"] = "failure"
    alerts["rule_name"] = "PasswordSpray"
    alerts["severity"] = "critical"
    alerts["confidence"] = 92
    alerts["reason"] = "Multiple failed logons from one source against many accounts."
    return alerts


def run_all_rules(df: pd.DataFrame) -> pd.DataFrame:
    results = [
        detect_suspicious_powershell(df),
        detect_runkey_persistence(df),
        detect_office_spawned_shell(df),
        detect_password_spray(df),
    ]

    non_empty = [r for r in results if not r.empty]
    if not non_empty:
        return pd.DataFrame()

    alerts = pd.concat(non_empty, ignore_index=True, sort=False)
    alerts = alerts.sort_values(["confidence", "timestamp"], ascending=[False, False]).reset_index(drop=True)
    return alerts