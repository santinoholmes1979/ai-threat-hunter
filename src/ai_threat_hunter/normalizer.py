from __future__ import annotations

import pandas as pd

from .config import RAW_LOG_FILE, NORMALIZED_LOG_FILE

EXPECTED_COLUMNS = [
    "timestamp",
    "event_type",
    "user",
    "host",
    "source_ip",
    "parent_process",
    "process_name",
    "command_line",
    "target_user",
    "registry_path",
    "destination_ip",
    "destination_port",
    "status",
]


def normalize_logs(input_path=RAW_LOG_FILE, output_path=NORMALIZED_LOG_FILE) -> pd.DataFrame:
    df = pd.read_csv(input_path)

    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df = df[EXPECTED_COLUMNS].copy()

    for col in ["event_type", "user", "host", "source_ip", "parent_process", "process_name", "status"]:
        df[col] = df[col].fillna("").astype(str).str.lower()

    df["command_line"] = df["command_line"].fillna("").astype(str)
    df["registry_path"] = df["registry_path"].fillna("").astype(str)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df.to_csv(output_path, index=False)
    return df


if __name__ == "__main__":
    df = normalize_logs()
    print(f"Normalized {len(df)} events to {NORMALIZED_LOG_FILE}")