from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

# Resolve project root whether you run from root or analysis/
here = Path(__file__).resolve()
root = here.parents[1] if (here.parent.name == 'analysis') else Path.cwd()

results_dir = root / 'results'
fig_dir = root / 'docs' / 'figures'
fig_dir.mkdir(parents=True, exist_ok=True)

# Load CSVs
s1 = pd.read_csv(results_dir / 'summary_vulnerable.csv')
s2 = pd.read_csv(results_dir / 'summary_secure.csv')
df = pd.concat([s1, s2], ignore_index=True)

# --- Confidentiality comparison ---
plt.figure(figsize=(6,4))
plt.bar(df['scenario'], df['confidentiality_pct'])
plt.ylabel('Confidentiality (%)')
plt.title('System-1 vs System-2 Confidentiality')
plt.tight_layout()
plt.savefig(fig_dir / 'confidentiality_compare.png', dpi=200)
plt.close()

# --- Latency & Energy (dual-axis) ---
fig, ax1 = plt.subplots(figsize=(7,4))
ax2 = ax1.twinx()
ax1.bar(df['scenario'], df['avg_latency_ms'], alpha=0.7, label='Latency (ms)')
ax2.plot(df['scenario'], df['energy_mJ_total'], marker='o', label='Energy (mJ)')
ax1.set_ylabel('Latency (ms)')
ax2.set_ylabel('Energy (mJ)')
plt.title('Latency & Energy Comparison')
fig.tight_layout()
plt.savefig(fig_dir / 'latency_energy.png', dpi=200)
plt.close()

# --- Detectability (System-2 only) ---
if 'eav_detect_rate' in s2.columns:
    plt.figure(figsize=(5,3))
    plt.bar(['Eve Detectability'], [s2['eav_detect_rate'].iloc[0]])
    plt.ylabel('Detection Rate (%)')
    plt.title('Eavesdropper Detectability in System-2')
    plt.tight_layout()
    plt.savefig(fig_dir / 'detectability.png', dpi=200)
    plt.close()

print('✅ Plots saved in', fig_dir)
