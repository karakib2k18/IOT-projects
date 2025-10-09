import numpy as np
import hashlib

class GatewayKeygen:
    """
    >>> Advanced key generation at the gateway:
    - Quantize TDD-reciprocal CSI from ED<->GW
    - Minimal reconciliation by majority (simulated)
    - Privacy amplification (BLAKE2s) -> session key
    Returns (key_bytes, csi_agreement)
    """
    def __init__(self, bits: int = 128, quant_levels: int = 4, seed: int = 1337):
        self.bits = int(bits)
        self.quant_levels = int(quant_levels)
        self.rng = np.random.default_rng(seed)

    def _quantize(self, csi: np.ndarray) -> np.ndarray:
        # uniform scalar quantization into L regions, then to bits
        qs = np.digitize(
            csi,
            np.quantile(csi, np.linspace(0, 1, self.quant_levels + 1)[1:-1])
        )
        width = int(np.ceil(np.log2(self.quant_levels)))
        out = np.zeros((len(qs), width), dtype=np.uint8)
        for i, v in enumerate(qs):
            for b in range(width):
                out[i, width - 1 - b] = (v >> b) & 1
        return out.flatten()

    def _amplify(self, bits: np.ndarray) -> bytes:
        b = bytes(np.packbits(bits).tolist())
        return hashlib.blake2s(b, digest_size=max(16, self.bits // 8)).digest()

    def derive_key(self, ed_csi: np.ndarray, gw_csi: np.ndarray):
        q_ed = self._quantize(ed_csi)
        q_gw = self._quantize(gw_csi)
        n = min(len(q_ed), len(q_gw), self.bits * 2)
        q_ed, q_gw = q_ed[:n], q_gw[:n]
        agree = float((q_ed == q_gw).mean())
        # toy reconciliation: if mismatch, XOR; otherwise take gw slice
        q_use = q_gw if agree >= 0.8 else ((q_ed ^ q_gw).astype(np.uint8))
        return self._amplify(q_use[: (self.bits * 2)]), agree
