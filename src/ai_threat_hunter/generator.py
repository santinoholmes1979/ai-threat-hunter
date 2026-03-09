from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from .config import RAW_LOG_FILE

USERS = ["alice", "bob", "charlie", "david", "eve", "frank", "grace"]
HOSTS = ["WS-1001", "WS-1002", "WS-1003", "ENG-2201", "HR-4401", "DC-01"]
IPS = ["10.0.0.15", "10.0.0.22", "10.0.1.10", "10.0.5.55", "192.168.1.20"]
PARENTS = ["explorer.exe", "winword.exe", "excel.exe", "outlook.exe", "services.exe", "cmd.exe"]
PROCESSES = ["powershell.exe", "cmd.exe", "rundll32.exe", "reg.exe", "wmic.exe", "notepad.exe"]
EVENT_TYPES = ["process_start", "auth_failure", "auth_success", "registry_change", "network_connection"]

SUSPICIOUS_COMMANDS = [
    "powershell.exe -EncodedCommand SQBFAFgA",
    "powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBtAGkAbQBpAGsAYQB0AHoA",
    "cmd.exe /c whoami && net user",
    "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d malware.exe",
    "wmic process call create powershell.exe",
]

BENIGN_COMMANDS = [
    "notepad.exe notes.txt",
    "powershell.exe Get-Process",
    "cmd.exe /c dir",
    "reg.exe query HKLM\\Software",
    "wmic cpu get name",
]


def generate_event(ts: datetime) -> dict:
    event_type = random.choices(
        EVENT_TYPES,
        weights=[45, 20, 10, 10, 15],
        k=1
    )[0]

    user = random.choice(USERS)
    host = random.choice(HOSTS)
    src_ip = random.choice(IPS)
    parent = random.choice(PARENTS)
    process = random.choice(PROCESSES)

    command_line = random.choice(BENIGN_COMMANDS)
    if random.random() < 0.12:
        command_line = random.choice(SUSPICIOUS_COMMANDS)

    return {
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "user": user,
        "host": host,
        "source_ip": src_ip,
        "parent_process": parent,
        "process_name": process,
        "command_line": command_line,
        "target_user": random.choice(USERS),
        "registry_path": random.choice([
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "",
            ""
        ]),
        "destination_ip": random.choice(IPS),
        "destination_port": random.choice([80, 135, 139, 443, 445, 3389]),
        "status": random.choice(["success", "failure"]),
    }


def generate_dataset(num_events: int = 300) -> pd.DataFrame:
    start = datetime.now() - timedelta(hours=12)
    rows = []

    for i in range(num_events):
        ts = start + timedelta(minutes=i * random.randint(1, 3))
        rows.append(generate_event(ts))

    df = pd.DataFrame(rows)

    spray_ip = "10.9.9.9"
    spray_time = datetime.now() - timedelta(hours=1)
    spray_rows = []

    for user in USERS:
        spray_rows.append({
            "timestamp": (spray_time + timedelta(seconds=len(spray_rows) * 20)).isoformat(),
            "event_type": "auth_failure",
            "user": user,
            "host": "WS-1002",
            "source_ip": spray_ip,
            "parent_process": "",
            "process_name": "",
            "command_line": "",
            "target_user": user,
            "registry_path": "",
            "destination_ip": "",
            "destination_port": "",
            "status": "failure",
        })

    df = pd.concat([df, pd.DataFrame(spray_rows)], ignore_index=True)
    return df.sort_values("timestamp").reset_index(drop=True)


def save_dataset(path: Path = RAW_LOG_FILE, num_events: int = 300) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    df = generate_dataset(num_events=num_events)
    df.to_csv(path, index=False)
    return df


if __name__ == "__main__":
    df = save_dataset()
    print(f"Generated {len(df)} events at {RAW_LOG_FILE}")