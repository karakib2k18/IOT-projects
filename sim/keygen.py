import numpy as np, hashlib

class GatewayKeygen:
    """
    Lightweight channel-reciprocity key generator (TDD).
    Generates a shared key from ED/GW CSI with simple bit-slicing
    and privacy amplification (SHA-256 truncation).
    """
    def __init__(self, bits=128):
        self.bits = bits

    def bit_slice(self, csi: np.ndarray) -> np.ndarray:
        med = np.median(csi)
        return (csi > med).astype(np.uint8)

    def privacy_amplify(self, q: np.ndarray) -> bytes:
        b = bytes(np.packbits(q))
        return hashlib.sha256(b).digest()[: self.bits // 8]

    def derive_key(self, csi_ed: np.ndarray, csi_gw: np.ndarray):
        """
        Returns: (key_bytes, csi_agreement_fraction)
        """
        q_ed = self.bit_slice(csi_ed)
        q_gw = self.bit_slice(csi_gw)
        agree = float((q_ed == q_gw).mean())
        # minimal reconciliation (simulation)
        q_use = q_gw if agree >= 0.8 else ((q_ed + q_gw) % 2).astype(np.uint8)
        return self.privacy_amplify(q_use), agree
