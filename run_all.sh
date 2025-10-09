#!/usr/bin/env bash
set -euo pipefail

# Always run from this script's directory (handles spaces in path)
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1) venv + minimal deps
python3 -m venv venv
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
pip install -q pytest nbconvert ipykernel

# 2) Run simulations
python3 sim/runner_vulnerable.py
python3 sim/runner_secure.py

# 3) Compare summaries
# python3 analysis/compare_s1_s2.py

# 4) Tests
pytest -q tests/test_vulnerability.py tests/test_secure.py

# 5) Plots
mkdir -p analysis docs/figures
if [ -f analysis/plots.ipynb ]; then
  # Execute the notebook and save executed copy into analysis/
  jupyter nbconvert --to notebook --execute "analysis/plots.ipynb" \
    --output "plots_executed" --output-dir "analysis" \
    --ExecutePreprocessor.timeout=300
else
  # Tiny fallback if the notebook isn't there
  python3 - <<'PY'
import pandas as pd, matplotlib.pyplot as plt
from pathlib import Path
root = Path(__file__).resolve().parent
df = pd.concat([
    pd.read_csv(root/"results/summary_vulnerable.csv"),
    pd.read_csv(root/"results/summary_secure.csv")
], ignore_index=True)
(root/"docs/figures").mkdir(parents=True, exist_ok=True)
df.plot(x="scenario", y="confidentiality_pct", kind="bar")
plt.tight_layout(); plt.savefig(root/"docs/figures/confidentiality_compare.png", dpi=200); plt.close()
PY
fi

echo "Done. Results in results/, executed notebook at analysis/plots_executed.ipynb (if present), figures in docs/figures/."
