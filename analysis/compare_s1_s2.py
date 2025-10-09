import pandas as pd
from pathlib import Path

root = Path(__file__).resolve().parents[1]
s1 = pd.read_csv(root / "results" / "summary_vulnerable.csv")
s2 = pd.read_csv(root / "results" / "summary_secure.csv")
df = pd.concat([s1, s2], ignore_index=True)
print("\n=== System-1 vs System-2 Summary ===")
print(df.to_string(index=False))
