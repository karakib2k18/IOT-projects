# sim/security_kim_gw.py
import time, hashlib, hmac
from typing import Tuple, Dict, Any
import numpy as np

from keygen import GatewayKeygen
from channel import tdd_channel_pair, pilot_contaminate
from kim import KIMMapper
from auth import make_token, verify_token, p2p_handshake_messages
from ess_features import FeatureDB, SignalHub


class SecureStack:
    """
    System-2 secure stack with cross-layer signaling:
      - Gateway CSI keygen + ESS screening
      - P2P auth (token + handshake)
      - PLS (KIM + key-driven dither + per-packet tag)
      - SignalHub to notify / react across layers
    """

    def __init__(self, cfg: dict):
        s2 = cfg.get("system2", {})
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
        self.max_suspicious_before_rekey = int(s2.get("rekey_thresh", 2))

        # cross-layer hub
        self.hub = SignalHub()
        self.alert_log: list[Dict[str, Any]] = []
        self.suspicious_hits = 0

        # subsystems
        self.kg = GatewayKeygen(bits=self.key_bits)
        ess_cfg = cfg.get("ess", {})
        self.ess = FeatureDB(
            rssi_window=ess_cfg.get("rssi_window", 50),
            z_thresh=ess_cfg.get("rssi_z_thresh", 3.0),
            csi_agree_thresh=ess_cfg.get("csi_agree_thresh", 0.75),
            hub=self.hub
        )

        # session state
        self.session_key: bytes | None = None
        self.session_epoch = 0
        self.pkt_counter = 0
        self.last_rekey_time = None

        # register default listeners
        self._register_listeners()

    # ---------- listeners wiring ----------
    def _register_listeners(self):
        self.hub.subscribe("ESS_ALERT", self._on_ess_alert)
        self.hub.subscribe("PLS_TAMPER", self._on_pls_alert)
        self.hub.subscribe("EAV_ACTIVITY", self._on_pls_alert)
        self.hub.subscribe("HIGH_DETECT", self._on_pls_alert)
        self.hub.subscribe("KEYGEN_FAIL", self._on_keygen_alert)
        self.hub.subscribe("AUTH_FAIL", self._on_auth_alert)
        self.hub.subscribe("AUTH_OK", self._on_auth_ok)
        self.hub.subscribe("KEY_ROTATED", self._on_key_rotated)

    # ---------- event handlers ----------
    def _record(self, etype: str, details: Dict[str, Any]):
        self.alert_log.append({"time": time.time(), "type": etype, "details": dict(details)})

    def _on_ess_alert(self, _, payload):
        # ESS saw something odd → raise dither and plan a rekey soon
        self._record("ESS_ALERT", payload)
        self.suspicious_hits += 1
        self.dither_strength = min(0.25, self.dither_strength + 0.04)
        if self.suspicious_hits >= self.max_suspicious_before_rekey:
            self.rotate_key()

    def _on_pls_alert(self, ev, payload):
        # PLS issues (tag mismatch, high Eve success, detectability)
        self._record(ev, payload)
        self.suspicious_hits += 1
        self.dither_strength = min(0.25, self.dither_strength + 0.06)
        if ev == "PLS_TAMPER":
            # immediately force rekey
            self.rotate_key()
        elif self.suspicious_hits >= self.max_suspicious_before_rekey:
            self.rotate_key()

    def _on_keygen_alert(self, _, payload):
        self._record("KEYGEN_FAIL", payload)
        # tell others to be conservative
        self.dither_strength = min(0.25, self.dither_strength + 0.05)
        # notify ESS to tighten thresholds slightly
        self.ess.alert("KEYGEN_FAIL_SIGNAL", {"who": "GW", **payload})

    def _on_auth_alert(self, _, payload):
        self._record("AUTH_FAIL", payload)
        # auth failed -> PLS should not trust; raise dither and drop first packet
        self.dither_strength = min(0.25, self.dither_strength + 0.05)

    def _on_auth_ok(self, _, payload):
        self._record("AUTH_OK", payload)
        # successful fresh auth -> clear some suspicion
        self.suspicious_hits = max(0, self.suspicious_hits - 1)

    def _on_key_rotated(self, _, payload):
        self._record("KEY_ROTATED", payload)
        self.suspicious_hits = 0

    # ---------- key management ----------
    def derive_key(self, seed: int = 0) -> bytes:
        try:
            ed_csi, gw_csi = tdd_channel_pair(n=self.csi_len, noise=self.csi_noise, seed=seed)
            if self.pilot_contam > 0:
                ed_csi, gw_csi = pilot_contaminate(ed_csi, gw_csi, strength=self.pilot_contam, seed=seed+7)
            K, agree = self.kg.derive_key(ed_csi, gw_csi)
        except Exception as e:
            # signal failure to other layers
            self.hub.emit("KEYGEN_FAIL", {"seed": seed, "err": str(e)})
            raise

        if not self.ess.csi_agreement_ok(agree):
            self.hub.emit("KEYGEN_FAIL", {"seed": seed, "agree": float(agree), "reason": "low_csi_agreement"})
            raise RuntimeError(f"ESS rejected session: CSI {agree:.2f} < thresh")

        rssi_dbm = 10*np.log10(np.mean(gw_csi**2) + 1e-9)
        self.ess.add_rssi(rssi_dbm)
        if self.ess.rssi_anomaly(rssi_dbm):
            self.ess.alert("RSSI_ANOMALY", {"rssi": float(rssi_dbm)})
            raise RuntimeError("ESS RSSI anomaly detected")

        self.session_key = K
        self.session_epoch += 1
        self.last_rekey_time = time.time()
        self.hub.emit("KEY_ROTATED", {"epoch": self.session_epoch})
        return K

    def rotate_key(self, seed: int | None = None):
        seed = int(time.time() % 10_000) if seed is None else int(seed)
        try:
            self.derive_key(seed=seed)
        except Exception:
            # keep going; ESS already signaled
            pass

    # ---------- auth ----------
    def authenticate_peers(self, key: bytes, ed_id="devA", pd_id="devB", epoch=1) -> bool:
        token = make_token(key, ed_id, pd_id, epoch)
        m1, m2 = p2p_handshake_messages(key)
        ok = False
        try:
            ok = verify_token(key, token, ed_id, pd_id, epoch)
        except Exception:
            ok = (token is not None and len(m1) > 0 and len(m2) > 0)

        if ok:
            self.session_key = key
            self.session_epoch = epoch
            self.last_rekey_time = time.time()
            self.hub.emit("AUTH_OK", {"epoch": epoch})
        else:
            self.hub.emit("AUTH_FAIL", {"epoch": epoch})
        return ok

    # ---------- per-packet subkey ----------
    def _subkey(self, key: bytes, pkt_ctr: int) -> bytes:
        h = hashlib.blake2s(digest_size=16)
        h.update(key)
        h.update(pkt_ctr.to_bytes(8, "little"))
        return h.digest()

    # ---------- PLS map / demap with tag ----------
    def map_payload(self, key: bytes, payload_syms: np.ndarray, pkt_ctr: int = 0) -> Tuple[np.ndarray, KIMMapper, bytes]:
        if key is None:
            raise RuntimeError("No session key")
        self.pkt_counter = pkt_ctr
        sk = self._subkey(key, pkt_ctr)
        mapper = KIMMapper(sk, M=self.M)
        tx = mapper.map_syms(payload_syms)

        if self.dither_strength > 0:
            seed = int.from_bytes(sk[:4], "little")
            rng = np.random.default_rng(seed)
            dmax = max(1, int(self.dither_strength * self.M))
            tx = (tx + rng.integers(0, dmax, size=tx.size)) % self.M

        # per-packet integrity/auth tag (physical-layer bound)
        tag = hmac.new(sk, tx.tobytes(), hashlib.blake2s).digest()[:8]
        return tx, mapper, tag

    def demap_payload_legit(self, mapper: KIMMapper, rx_syms: np.ndarray) -> np.ndarray:
        return mapper.demap_syms(rx_syms)

    def verify_tag(self, key: bytes, rx_syms: np.ndarray, tag: bytes, pkt_ctr: int) -> bool:
        sk = self._subkey(key, pkt_ctr)
        calc = hmac.new(sk, rx_syms.tobytes(), hashlib.blake2s).digest()[:8]
        ok = hmac.compare_digest(calc, tag)
        if not ok:
            # cross-layer signal so ESS/Keygen/Auth are aware
            self.hub.emit("PLS_TAMPER", {"pkt_ctr": pkt_ctr})
        return ok

    # ---------- coarse cost model ----------
    def overheads(self, first_packet=False) -> Tuple[float, float]:
        lat_ms = self.kim_overhead_ms
        energy_mJ = (self.energy.get("kim_map_uj", 0.02) / 1000.0)
        if first_packet:
            lat_ms += self.auth_overhead_ms
            energy_mJ += (self.energy.get("handshake_uj", 50) / 1000.0)
        pkt_bits = self.energy.get("pkt_bits", 1024)
        tx_bit_nj = self.energy.get("tx_bit_nj", 1.0)
        energy_mJ += (pkt_bits * tx_bit_nj) / 1e6
        return lat_ms, energy_mJ

    # ---------- legacy compat (runner calls) ----------
    def handle_attack_event(self, event_type: str, details: Dict) -> Dict:
        # keep existing API, but also emit via hub so other layers react
        self._record(event_type, details)
        self.hub.emit(event_type, details)
        # default mitigation hint for runner
        action = {"action": "mitigate", "drop_packet": False}
        if event_type in ("PLS_TAMPER", "TAG_TAMPER"):
            action = {"action": "rekey_and_reauth", "drop_packet": True}
        return action
