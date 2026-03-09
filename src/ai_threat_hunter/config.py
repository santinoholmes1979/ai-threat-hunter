from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
HUNTS_FILE = BASE_DIR / "hunts" / "hunt_prompts.yml"

RAW_LOG_FILE = DATA_DIR / "raw_events.csv"
NORMALIZED_LOG_FILE = DATA_DIR / "normalized_events.csv"
ALERTS_FILE = DATA_DIR / "alerts.csv"