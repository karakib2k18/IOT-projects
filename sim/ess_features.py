import collections, math

class FeatureDB:
    """
    Lightweight ESS feature DB for gateway intelligence.
    Tracks RSSI samples and basic CSI agreement to validate peers.
    """
    def __init__(self, rssi_window=50, z_thresh=3.0, csi_agree_thresh=0.75):
        self.rssi_window = rssi_window
        self.z_thresh = z_thresh
        self.csi_agree_thresh = csi_agree_thresh
        self._rssi = collections.deque(maxlen=rssi_window)

    def add_rssi(self, rssi_dbm: float):
        self._rssi.append(rssi_dbm)

    def _rssi_stats(self):
        if not self._rssi:
            return (0.0, 1.0)
        m = sum(self._rssi)/len(self._rssi)
        v = sum((x-m)**2 for x in self._rssi)/max(1, len(self._rssi)-1)
        s = math.sqrt(max(v, 1e-9))
        return (m, s)

    def rssi_anomaly(self, current_dbm: float) -> bool:
        mean, std = self._rssi_stats()
        if std < 1e-6:
            return False
        z = abs((current_dbm - mean)/std)
        return z > self.z_thresh

    def csi_agreement_ok(self, frac_equal: float) -> bool:
        return frac_equal >= self.csi_agree_thresh
