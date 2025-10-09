import numpy as np

class KIMMapper:
    """
    Key-Indexed Mapping (KIM): permutes M-ary symbols with a key-derived permutation.
    Without the key, Eve's demapping has high BER; legit peer applies inverse perm.

    >>> Where PLS happens:
    The permutation derived from the session key is applied in map_syms() and
    inverted in demap_syms(). Without the right key, the symbol order is wrong,
    causing high BER for an eavesdropper.
    """
    def __init__(self, key_bytes: bytes, M: int = 16):
        self.M = int(M)
        self.perm = self._build_perm(key_bytes)
        self.inv = np.argsort(self.perm)

    def _build_perm(self, key_bytes: bytes):
        # Seed PRNG from the session key, then build a permutation over M symbols
        seed = int.from_bytes(key_bytes[:4], 'little', signed=False)
        rng = np.random.default_rng(seed)
        perm = np.arange(self.M)
        rng.shuffle(perm)
        return perm

    def map_syms(self, symbols: np.ndarray) -> np.ndarray:
        # Apply key-indexed permutation (PLS)
        return self.perm[symbols % self.M]

    def demap_syms(self, rx_symbols: np.ndarray) -> np.ndarray:
        # Invert permutation at the legit receiver
        return self.inv[rx_symbols % self.M]
