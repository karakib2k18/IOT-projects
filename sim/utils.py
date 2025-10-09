import pandas as pd
from pathlib import Path

def _ensure_dir(p: str | Path):
    Path(p).parent.mkdir(parents=True, exist_ok=True)

def save_logs(rows, path: str):
    _ensure_dir(path)
    pd.DataFrame(rows).to_csv(path, index=False)

def save_summary(summary: dict, path: str):
    _ensure_dir(path)
    pd.DataFrame([summary]).to_csv(path, index=False)
