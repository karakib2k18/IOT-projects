#!/bin/bash
set -euo pipefail

# -------------------------
# 1) Move to project root
# -------------------------
# Replace with your path if needed, or run this while in the project folder.
cd "$(pwd)"

# -------------------------
# 2) Virtualenv + install
# -------------------------
python3 -m venv venv
# activate
source venv/bin/activate

# install main requirements
pip install --upgrade pip
pip install -r requirements.txt

# optional useful tools (for tests & notebook execution)
pip install pytest jupyter

# quick dependency sanity check
python3 - <<'PY'
import sys
import importlib
for pkg in ("yaml","networkx","pandas","numpy","matplotlib"):
    try:
        importlib.import_module(pkg)
    except Exception as e:
        print(f"ERROR importing {pkg}: {e}")
        raise
print("All imports OK")
PY

# -------------------------
# 3) Run System-1 (Vulnerable)
# -------------------------
echo "=== Running System-1 (vulnerable) ==="
python3 sim/runner_vulnerable.py
echo "System-1 done. summary -> results/summary_vulnerable.csv"

# -------------------------
# 4) Run System-2 (Secure)
# -------------------------
echo "=== Running System-2 (secure) ==="
python3 sim/runner_secure.py
echo "System-2 done. summary -> results/summary_secure.csv"

# -------------------------
# 5) Compare summaries (print to console)
# -------------------------
echo "=== Comparing System-1 vs System-2 ==="
python3 analysis/compare_s1_s2.py

# -------------------------
# 6) Run unit tests (after both runs)
# -------------------------
echo "=== Running tests ==="
pytest -q tests/test_vulnerability.py tests/test_secure.py || {
  echo "One or more tests failed — check the trace above";
  exit 1
}
echo "Tests passed."

# -------------------------
# 7) Generate PNG plots
# 7a: Try to execute the notebook (preferred)
# -------------------------
if command -v jupyter >/dev/null 2>&1; then
  echo "Executing analysis/plots.ipynb (will create PNGs in docs/figures/)"
  mkdir -p docs/figures
  jupyter nbconvert --to notebook --execute analysis/plots.ipynb --output analysis/plots_executed.ipynb --ExecutePreprocessor.timeout=120
  echo "Notebook executed; PNGs saved in docs/figures/"
else
  echo "jupyter not found. Creating a quick plotting script and running it."
  mkdir -p docs/figures
  cat > analysis/plot_results.py <<'PY'
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

root = Path(__file__).resolve().parents[1]
s1f = root / "results" / "summary_vulnerable.csv"
s2f = root / "results" / "summary_secure.csv"
s1 = pd.read_csv(s1f) if s1f.exists() else None
s2 = pd.read_csv(s2f) if s2f.exists() else None

# combined df for bar charts
dfs = []
if s1 is not None:
    dfs.append(s1)
if s2 is not None:
    dfs.append(s2)
if dfs:
    df = pd.concat(dfs, ignore_index=True)
    # Confidentiality
    plt.figure(figsize=(6,4))
    plt.bar(df['scenario'], df['confidentiality_pct'], color=['salmon' if 'Vulner' in s else 'skyblue' for s in df['scenario']])
    plt.ylabel('Confidentiality (%)')
    plt.title('System-1 vs System-2 Confidentiality')
    plt.tight_layout()
    plt.savefig(root / 'docs' / 'figures' / 'confidentiality_compare.png', dpi=200)
    plt.close()

    # Latency & Energy
    fig, ax1 = plt.subplots(figsize=(7,4))
    ax2 = ax1.twinx()
    ax1.bar(df['scenario'], df['avg_latency_ms'], color='lightgreen', alpha=0.7, label='Latency (ms)')
    ax2.plot(df['scenario'], df['energy_mJ_total'], color='orange', marker='o', label='Energy (mJ)')
    ax1.set_ylabel('Latency (ms)')
    ax2.set_ylabel('Energy (mJ)')
    plt.title('Latency & Energy Comparison')
    fig.tight_layout()
    plt.savefig(root / 'docs' / 'figures' / 'latency_energy.png', dpi=200)
    plt.close()

# Detectability (System-2 only)
if s2 is not None and 'eav_detect_rate' in s2.columns:
    plt.figure(figsize=(5,3))
    plt.bar(['Eve Detectability'], [s2['eav_detect_rate'].iloc[0]], color='gray')
    plt.ylabel('Detection Rate (%)')
    plt.title('Eavesdropper Detectability in System-2')
    plt.tight_layout()
    plt.savefig(root / 'docs' / 'figures' / 'detectability.png', dpi=200)
    plt.close()

print("Plots saved to docs/figures/")
PY
  python3 analysis/plot_results.py
fi

# -------------------------
# 8) Summary / Next actions message
# -------------------------
echo "=== DONE ==="
echo "Files created/updated:"
echo " - results/summary_vulnerable.csv"
echo " - results/logs_vulnerable.csv"
echo " - results/summary_secure.csv"
echo " - results/logs_secure.csv"
echo " - docs/figures/* (confidentiality_compare.png, latency_energy.png, detectability.png) if plotting succeeded"
echo
echo "If you hit any error, copy & paste the traceback here and I'll help fix it."
