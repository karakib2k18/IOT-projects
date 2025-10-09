import numpy as np
from keygen import GatewayKeygen
from channel import tdd_channel_pair, pilot_contaminate
from kim import KIMMapper
from auth import make_token, verify_token, p2p_handshake_messages
from ess_features import FeatureDB

class SecureStack:
    """
    System-2 secure stack:
    - Gateway-assisted keygen (TDD reciprocity)
    - Peer authentication (HMAC token + 2-step nonce handshake)
    - Key-Integrated Modulation (KIM + key-driven dither)
    - Optional multipath/pilot contamination stress (affects Eve model)
    Lightweight overheads are accounted for in latency/energy.
    """
    def __init__(self, cfg):
        s2 = cfg["system2"]
        self.M = int(s2.get("M", 16))
        self.key_bits = int(s2.get("key_bits", 128))
        self.csi_len = int(s2.get("csi_len", 256))
        self.csi_noise = float(s2.get("csi_noise", 0.05))
        self.multipath_strength = float(s2.get("multipath_strength", 0.0))
        self.pilot_contam = float(s2.get("pilot_contamination", 0.0))
        self.dither_strength = float(s2.get("dither_strength", 0.0))
        self.auth_overhead_ms = int(s2.get("auth_overhead_ms", 3))
        self.kim_overhead_ms = int(s2.get("kim_overhead_ms", 5))
        self.energy = s2.get("energy", {"handshake_uj":50, "kim_map_uj":0.02, "tx_bit_nj":1.0, "pkt_bits":1024})

        self.kg = GatewayKeygen(bits=self.key_bits)
        ess_cfg = cfg.get("ess", {})
        self.ess = FeatureDB(
            rssi_window=ess_cfg.get("rssi_window", 50),
            z_thresh=ess_cfg.get("rssi_z_thresh", 3.0),
            csi_agree_thresh=ess_cfg.get("csi_agree_thresh", 0.75),
        )

    def derive_key(self, seed=0):
        from channel import tdd_channel_pair
        ed_csi, gw_csi = tdd_channel_pair(n=self.csi_len, noise=self.csi_noise, seed=seed)
        if self.pilot_contam > 0:
            ed_csi, gw_csi = pilot_contaminate(ed_csi, gw_csi, strength=self.pilot_contam, seed=seed+7)
        K, agree = self.kg.derive_key(ed_csi, gw_csi)
        # ESS checks
        if not self.ess.csi_agreement_ok(agree):
            raise RuntimeError(f"ESS rejected session: CSI agreement {agree:.2f} < thresh")
        # simulate RSSI learning (use CSI energy as proxy)
        rssi_dbm = 10*np.log10(np.mean(gw_csi**2) + 1e-9)
        self.ess.add_rssi(rssi_dbm)
        if self.ess.rssi_anomaly(rssi_dbm):
            raise RuntimeError("ESS RSSI anomaly detected")
        return K

    def authenticate_peers(self, key: bytes, ed_id="devA", pd_id="devB", epoch=1):
        token = make_token(key, ed_id, pd_id, epoch)
        m1, m2 = p2p_handshake_messages(key)
        # minimal verification (simulation)
        ok = token is not None and len(m1) > 0 and len(m2) > 0
        return ok

    def map_payload(self, key: bytes, payload_syms: np.ndarray):
        """
        Key-Integrated Modulation:
        1) Key-indexed permutation (KIM)
        2) Key-driven dither: add small PRNG offset per symbol -> spectral camouflage.
        """
        mapper = KIMMapper(key, M=self.M)
        tx_perm = mapper.map_syms(payload_syms)
        # key-driven dither
        if self.dither_strength > 0:
            seed = int.from_bytes(key[:4], 'little', signed=False)
            rng = np.random.default_rng(seed)
            dither = rng.integers(0, max(1, int(self.dither_strength*self.M)), size=tx_perm.size)
            tx_perm = (tx_perm + dither) % self.M
        return tx_perm, mapper

    def demap_payload_legit(self, mapper, rx_syms: np.ndarray):
        return mapper.demap_syms(rx_syms)

    def overheads(self, first_packet=False):
        lat_ms = self.kim_overhead_ms
        energy_mJ = 0.0
        # convert µJ / nJ to mJ
        energy_mJ += (self.energy.get("kim_map_uj",0.02) / 1000.0)
        if first_packet:
            lat_ms += self.auth_overhead_ms
            energy_mJ += (self.energy.get("handshake_uj",50) / 1000.0)
        # CPU per-packet bit processing (very rough)
        pkt_bits = self.energy.get("pkt_bits",1024)
        tx_bit_nj = self.energy.get("tx_bit_nj",1.0)
        energy_mJ += (pkt_bits * tx_bit_nj) / 1e6
        return lat_ms, energy_mJ
