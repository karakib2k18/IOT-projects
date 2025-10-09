import pandas as pd
from pathlib import Path

root = Path(__file__).resolve().parents[1]
s = pd.read_csv(root / "results" / "summary_vulnerable.csv")
print("\n=== System 1 – Vulnerable Summary ===")
print(s.to_string(index=False))
