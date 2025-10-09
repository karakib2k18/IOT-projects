import numpy as np

class KIMMapper:
    """
    Key-Indexed Mapping (KIM): permutes M-ary symbols with a key-derived permutation.
    Without the key, Eve's demapping has high BER; legit peer applies inverse perm.
    """
    def __init__(self, key_bytes: bytes, M=16):
        self.M = M
        self.perm = self._build_perm(key_bytes)
        self.inv = np.argsort(self.perm)

    def _build_perm(self, key_bytes: bytes):
        seed = int.from_bytes(key_bytes[:4], 'little', signed=False)
        rng = np.random.default_rng(seed)
        perm = np.arange(self.M)
        rng.shuffle(perm)
        return perm

    def map_syms(self, symbols):
        return self.perm[symbols % self.M]

    def demap_syms(self, rx_symbols):
        return self.inv[rx_symbols % self.M]
