# sim/ess_features.py
from __future__ import annotations
import collections
from typing import Callable, Dict, Any, Optional
import numpy as np


class SignalHub:
    """
    Tiny pub/sub bus so PLS, ESS, Keygen/Auth can notify each other.
    - subscribe(event, callback)
    - emit(event, payload)
    """
    def __init__(self):
        self._subs: Dict[str, list[Callable[[str, Dict[str, Any]], None]]] = {}

    def subscribe(self, event: str, cb: Callable[[str, Dict[str, Any]], None]):
        self._subs.setdefault(event, []).append(cb)

    def emit(self, event: str, payload: Optional[Dict[str, Any]] = None):
        payload = {} if payload is None else payload
        for cb in self._subs.get(event, []):
            try:
                cb(event, payload)
            except Exception:
                # never let listeners kill the bus
                pass


class FeatureDB:
    """
    ESS (Environmental Security Sensor) features:
      - Maintain RSSI history, detect anomalies (z-score + absolute delta)
      - Validate CSI agreement fraction
      - Can raise ESS alerts via SignalHub
    """
    def __init__(self,
                 rssi_window: int = 50,
                 z_thresh: float = 3.0,
                 csi_agree_thresh: float = 0.75,
                 hub: Optional[SignalHub] = None):
        self.rssi_window = int(rssi_window)
        self.z_thresh = float(z_thresh)
        self.csi_agree_thresh = float(csi_agree_thresh)
        self.rssi_hist = collections.deque(maxlen=self.rssi_window)
        self.hub = hub or SignalHub()

    # ---- RSSI ----
    def add_rssi(self, rssi_dbm: float):
        try:
            self.rssi_hist.append(float(rssi_dbm))
        except Exception:
            pass

    def rssi_mean(self) -> Optional[float]:
        if not self.rssi_hist:
            return None
        return float(np.mean(self.rssi_hist))

    def rssi_std(self) -> float:
        if len(self.rssi_hist) < 2:
            return 0.0
        return float(np.std(self.rssi_hist, ddof=0))

    def rssi_anomaly(self, current_rssi_dbm: float, delta_threshold: float | None = None) -> bool:
        """
        Returns True if current RSSI is anomalous.
        Checks both z-score and absolute delta from running mean.
        """
        if len(self.rssi_hist) < 5:
            return False

        mu = self.rssi_mean()
        if mu is None:
            return False

        sigma = self.rssi_std()
        if sigma > 0:
            z = abs((current_rssi_dbm - mu) / sigma)
            if z >= self.z_thresh:
                return True

        if delta_threshold is not None:
            if abs(current_rssi_dbm - mu) >= float(delta_threshold):
                return True

        return False

    # ---- CSI agreement ----
    def csi_agreement_ok(self, agree_fraction: float) -> bool:
        try:
            a = float(agree_fraction)
        except Exception:
            a = 0.0
        return a >= self.csi_agree_thresh

    # ---- ESS alert helper ----
    def alert(self, reason: str, payload: Dict[str, Any] | None = None):
        self.hub.emit("ESS_ALERT", {"reason": reason, **(payload or {})})
