import pandas as pd
from pathlib import Path

def test_system2_confidentiality_improvement():
    root = Path(__file__).resolve().parents[1]
    s1 = pd.read_csv(root / 'results' / 'summary_vulnerable.csv')
    s2 = pd.read_csv(root / 'results' / 'summary_secure.csv')

    conf1 = float(s1['confidentiality_pct'].iloc[0])
    conf2 = float(s2['confidentiality_pct'].iloc[0])
    assert conf2 > conf1, f"Expected System-2 confidentiality ({conf2}) > System-1 ({conf1})"

def test_eavesdrop_detectability_low():
    root = Path(__file__).resolve().parents[1]
    s2 = pd.read_csv(root / 'results' / 'summary_secure.csv')
    det = float(s2.get('eav_detect_rate', [100])[0])
    assert det < 20.0, f"Eve detectability too high ({det}%)"

print('✅ test_secure.py loaded — run after both systems executed')
