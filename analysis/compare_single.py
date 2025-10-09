import pandas as pd
from pathlib import Path

root = Path(__file__).resolve().parents[1]
s1 = root / "results" / "summary_vulnerable.csv"
s2 = root / "results" / "summary_secure.csv"

if s1.exists():
    df = pd.read_csv(s1)
    print("\n=== System 1 – Vulnerable Summary ===")
    print(df.to_string(index=False))

if s2.exists():
    df = pd.read_csv(s2)
    print("\n=== System 2 – Secure Summary ===")
    print(df.to_string(index=False))
