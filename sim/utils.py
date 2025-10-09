import os
import pandas as pd

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def save_logs(logs: list[dict], path: str) -> None:
    ensure_dir(os.path.dirname(path))
    pd.DataFrame(logs).to_csv(path, index=False)

def save_summary(summary: dict, path: str) -> None:
    ensure_dir(os.path.dirname(path))
    pd.DataFrame([summary]).to_csv(path, index=False)
