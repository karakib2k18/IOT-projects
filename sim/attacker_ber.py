import numpy as np

class EveBER:
    """
    Eavesdropper estimates Bit Error Rate (BER) when key/KIM unknown.
    For M-ary symbols, naive demap ≈ 1 - 1/M. Multipath/pilot issues can worsen.
    You can refine by adding SNR-based models if desired.
    """
    def __init__(self, snr_db=18, antennas=1):
        self.snr_db = snr_db
        self.antennas = antennas

    def ber_without_key(self, M=16, multipath_strength=0.0, pilot_contam=0.0, snr_penalty_db=0.0):
        # Base BER for naive guess: 1 - 1/M
        ber = 1.0 - (1.0 / M)
        # Worsen with multipath/pilot contamination and SNR penalty (bounded at <1)
        ber = min(1.0, ber + 0.1 * multipath_strength + 0.05 * pilot_contam)
        if snr_penalty_db > 0:
            ber = min(1.0, ber + 0.02 * snr_penalty_db)
        # Antennas could help a bit (reduce BER), but without key it stays high
        ber = max(0.0, ber - 0.02 * (self.antennas - 1))
        return ber

    def ber_with_key(self):
        # Legit peer with key can demap exactly; BER ~ 0 if no channel noise modeled in symbols
        return 0.0

    def success_prob_from_ber(self, ber: float):
        # Probability Eve recovers correct content = 1 - BER (simplified)
        return max(0.0, 1.0 - ber)

    def detect_probability(self, M=16, dither_strength=0.0, base_threshold=0.25):
        """
        Activity detection (energy + structure).
        Key-dither increases spectral ambiguity, reducing detectability.
        We model detectability ~ base - f(dither) (clamped to [0,1]).
        """
        penalty = min(0.2, 0.15 * dither_strength)  # modest reduction
        p_det = max(0.0, min(1.0, base_threshold - penalty))
        return p_det
