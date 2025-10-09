import numpy as np

def tdd_channel_pair(n=256, noise=0.05, seed=0):
    """
    Generate correlated channel observations (ED and GW) in TDD (reciprocal).
    """
    rng = np.random.default_rng(seed)
    base = rng.normal(0, 1, n)
    ed_obs = base + rng.normal(0, noise, n)
    gw_obs = base + rng.normal(0, noise, n)
    return ed_obs, gw_obs

def add_multipath_signature(waveform: np.ndarray, strength=0.3, seed=1):
    rng = np.random.default_rng(seed)
    signature = rng.normal(0, 1, size=waveform.size)
    return waveform + strength * signature

def pilot_contaminate(ed_obs, gw_obs, strength=0.1, seed=7):
    rng = np.random.default_rng(seed)
    contam = rng.normal(0, strength, size=ed_obs.size)
    return ed_obs + contam, gw_obs + contam
