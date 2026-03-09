from __future__ import annotations

import yaml
import pandas as pd

from .config import HUNTS_FILE, ALERTS_FILE
from .detectors.rules import run_all_rules
from .summarizer import build_summary


def load_hunts() -> list[dict]:
    with open(HUNTS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("hunts", [])


def search_hunts(query: str, hunts: list[dict]) -> list[dict]:
    query_lower = query.lower()
    matched = []

    for hunt in hunts:
        haystack = " ".join([
            hunt.get("name", ""),
            hunt.get("description", ""),
            " ".join(hunt.get("keywords", []))
        ]).lower()

        if any(word in haystack for word in query_lower.split()):
            matched.append(hunt)

    return matched


def run_hunting_pipeline(df: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    alerts = run_all_rules(df)

    if not alerts.empty:
        alerts.to_csv(ALERTS_FILE, index=False)

    summary = build_summary(alerts)
    return alerts, summary