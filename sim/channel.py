import numpy as np

def tdd_channel_pair(n: int = 256, noise: float = 0.05, seed: int = 0):
    """
    >>> TDD reciprocity model:
    Produce two highly-correlated CSI sequences for ED<->GW (same fading block)
    """
    rng = np.random.default_rng(seed)
    base = rng.normal(size=n) * 0.8 + rng.normal(size=n) * 0.2
    ed = base + noise * rng.normal(size=n)
    gw = base + noise * rng.normal(size=n)
    # normalize
    ed = (ed - ed.mean()) / (ed.std() + 1e-9)
    gw = (gw - gw.mean()) / (gw.std() + 1e-9)
    return ed, gw

def pilot_contaminate(ed: np.ndarray, gw: np.ndarray, strength: float = 0.1, seed: int = 1):
    """
    >>> Pilot contamination stress: add correlated interference -> lowers CSI agreement
    """
    rng = np.random.default_rng(seed)
    contam = strength * rng.normal(size=len(ed))
    return ed + contam, gw + contam
