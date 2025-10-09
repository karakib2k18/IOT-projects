import pandas as pd
from pathlib import Path

root = Path(__file__).resolve().parents[1]
s1 = root / "results" / "summary_vulnerable.csv"
s2 = root / "results" / "summary_secure.csv"

if s1.exists() and s2.exists():
    df1 = pd.read_csv(s1)
    df2 = pd.read_csv(s2)
    df = pd.concat([df1, df2], ignore_index=True)
    print("\n=== System-1 vs System-2 Summary ===")
    print(df.to_string(index=False))
else:
    print("One or both summary files are missing in results/.")
