from __future__ import annotations

import pandas as pd


def safe_read_csv(path):
    try:
        return pd.read_csv(path)
    except FileNotFoundError:
        return pd.DataFrame()