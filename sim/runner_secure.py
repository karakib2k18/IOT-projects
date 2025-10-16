# runner_secure.py
import yaml
import networkx as nx
import numpy as np
import csv
from statistics import mean
from pathlib import Path
from typing import List

from topology import build_topology
from traffic import generate_messages
from utils import save_logs, save_summary
from security_kim_gw import SecureStack
from attacker_ber import EveBER

ROOT = Path(__file__).resolve().parents[1]

def save_alerts(alerts: List[dict], outpath: str):
    """Write alerts list to CSV for traceability."""
    if not alerts:
        # create an empty file so other scripts don't error
        with open(outpath, "w") as f:
            f.write("")
        return
    keys = set()
    for a in alerts:
        keys.update(a.keys())
    keys = sorted(keys)
    with open(outpath, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, "") for k in keys})

def run_secure(cfg: dict):
    G = build_topology(cfg)
    msgs = generate_messages(cfg)

    s2 = SecureStack(cfg)

    # Attempt initial key derivation; handle policy rekey attempts if allowed
    key = None
    try:
        key = s2.derive_key(seed=1)
    except RuntimeError as e:
        print("Key derivation failed:", e)
        # policy: attempt one rekey with a new seed if rekey_on_ess is allowed
        if s2.policy_rekey_on_ess:
            try:
                print("Attempting rekey (policy allowed)...")
                key = s2.derive_key(seed=2)
            except RuntimeError as e2:
                print("Rekey attempt failed:", e2)
                raise

    # Authenticate peers using P2P mechanism
    if not s2.authenticate_peers(key):
        # signal and abort (in simulation we treat auth failure as fatal)
        s2.signal_auth_alert("P2P_AUTH_FAIL")
        raise RuntimeError("P2P authentication failed in System-2")

    # Attacker / Eve model
    a2 = cfg.get("attacker2", {})
    eve = EveBER(snr_db=a2.get("snr_db",18), antennas=a2.get("antennas",1))
    detect_base = a2.get("detect_base_threshold", 0.25)

    # optional jammer (active attacker scenario)
    jcfg = cfg.get("jammer", {"enabled": False})
    jam_enabled = bool(jcfg.get("enabled", False))
    jam_duty = float(jcfg.get("duty_cycle", 0.1))
    jam_penalty = float(jcfg.get("snr_penalty_db", 6.0))

    logs = []
    delivered = 0
    intercepted = 0
    detections = 0
    latencies = []
    total_energy = 0.0

    alerts_accum = []   # to collect alerts during whole run

    first_packet = True
    for i, (src, dst, size_kB, tgen) in enumerate(msgs):
        # If policy requested rekey (alerts contain REKEY_*), perform rekey before sending
        pol_rekeys = [a for a in s2.alerts if a.get("who") == "POLICY" and a.get("code", "").startswith("REKEY")]
        age_exceeded = any(a.get("code") == "KEY_AGE_EXCEEDED" for a in s2.alerts)
        if pol_rekeys or age_exceeded:
            # attempt rekey with a seed derived from i to change channel draw
            try:
                print(f"[runner] policy requested rekey at msg {i}. Attempting rekey...")
                key = s2.derive_key(seed=1000 + i)
                # clear policy alerts after handling
                s2.alerts = []
            except RuntimeError as e:
                print("[runner] rekey attempt failed:", e)
                # We continue with older key — but an alert persists (already recorded)

        # build toy payload as M-ary symbols
        M = s2.M
        rng = np.random.default_rng(i)
        payload_syms = rng.integers(0, M, size=32)

        tx_perm, mapper = s2.map_payload(key, payload_syms)
        # Legit receiver
        rx_syms = tx_perm.copy()
        rx_payload = s2.demap_payload_legit(mapper, rx_syms)

        # jamming window (active attack degrades SNR perceived by Eve)
        snr_penalty = jam_penalty if (jam_enabled and (i % max(1, int(1/max(1e-6, jam_duty))) == 0)) else 0.0

        # Eve's BER when key unknown
        ber_eav = eve.ber_without_key(M=M,
                                      multipath_strength=s2.multipath_strength,
                                      pilot_contam=s2.pilot_contam,
                                      snr_penalty_db=snr_penalty)
        p_success = eve.success_prob_from_ber(ber_eav)
        was_intercepted = (np.random.default_rng(i+123).random() < p_success)
        if was_intercepted:
            intercepted += 1

        # detectability (activity detection)
        p_detect = eve.detect_probability(M=M, dither_strength=s2.dither_strength, base_threshold=detect_base)
        if np.random.default_rng(i+999).random() < p_detect:
            detections += 1

        # If detect rate crosses policy threshold, signal policy alert:
        # compute rolling detect rate roughly by considering detections/delivered so far (avoid division by zero)
        current_detect_pct = 100.0 * ( (detections) / max(1, delivered + 1) )  # +1 to be conservative
        if current_detect_pct > s2.policy_max_detect_pct:
            s2._push_alert("POLICY", "DETECT_RATE_EXCEEDED", {"pct": current_detect_pct})
            # runner can choose immediate reaction here; we'll attempt to rekey if allowed
            if s2.policy_rekey_on_ess:
                s2._push_alert("POLICY", "REKEY_REQUESTED", {"reason": "DETECT_RATE_EXCEEDED", "pct": current_detect_pct})

        # latency & energy: link + security overheads
        path = nx.shortest_path(G, src, dst)
        hop_latency = 0
        energy = 0.0
        for u, v in zip(path[:-1], path[1:]):
            hop_latency += G[u][v]["latency"]
            energy += cfg["tx_cost_mJ"]
        lat_ov, e_ov = s2.overheads(first_packet=first_packet)
        hop_latency += lat_ov
        energy += e_ov
        first_packet = False

        delivered += 1
        latencies.append(hop_latency)
        total_energy += energy

        # collect any alerts produced during map_payload call (or earlier)
        if s2.alerts:
            alerts_accum.extend(s2.alerts)
            # keep alerts for runner-level decisions as well (do not clear here)
            # but avoid infinite growth: keep last 1000
            if len(alerts_accum) > 5000:
                alerts_accum = alerts_accum[-5000:]

        logs.append({
            "src": src, "dst": dst, "path": "->".join(path),
            "latency_ms": hop_latency, "energy_mJ": energy,
            "eav_BER": round(ber_eav,4),
            "eav_success_prob": round(p_success,4),
            "eav_detect_prob": round(p_detect,4),
            "intercepted": was_intercepted
        })

    confidentiality = 100.0 * (1 - intercepted / max(1, delivered))
    summary = {
        "scenario": "System2_Secure",
        "confidentiality_pct": round(confidentiality, 2),
        "avg_latency_ms": round(mean(latencies), 2) if latencies else 0.0,
        "energy_mJ_total": round(total_energy, 2),
        "total_msgs": delivered,
        "intercepted": intercepted,
        "eav_detect_rate": round(100.0 * detections / max(1, delivered), 2)
    }

    return logs, summary, alerts_accum

if __name__ == "__main__":
    cfg_path = ROOT / "config" / "sim_config.yaml"
    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)

    logs, summary, alerts = run_secure(cfg)
    save_logs(logs, str(ROOT / "results" / "logs_secure.csv"))
    save_summary(summary, str(ROOT / "results" / "summary_secure.csv"))
    save_alerts(alerts, str(ROOT / "results" / "alerts_secure.csv"))

    print(summary)
    if alerts:
        print("Alerts recorded:", len(alerts))
        for a in alerts[:10]:
            print(" ", a)
