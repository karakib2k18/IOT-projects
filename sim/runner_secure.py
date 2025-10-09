import yaml, networkx as nx, numpy as np
from statistics import mean
from pathlib import Path

from topology import build_topology
from traffic import generate_messages
from utils import save_logs, save_summary
from security_kim_gw import SecureStack
from attacker_ber import EveBER

ROOT = Path(__file__).resolve().parents[1]

def run_secure(cfg: dict):
    G = build_topology(cfg)
    msgs = generate_messages(cfg)

    s2 = SecureStack(cfg)
    key = s2.derive_key(seed=1)
    assert s2.authenticate_peers(key), "P2P authentication failed in System-2"

    # Eve evaluates BER, then success prob = 1 - BER
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

    first_packet = True
    for i, (src, dst, size_kB, tgen) in enumerate(msgs):
        # secure data path: allow direct P2P after auth (shortest path)
        path = nx.shortest_path(G, src, dst)

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

        # latency & energy: link + security overheads
        hop_latency = 0
        energy = 0.0
        for u, v in zip(path[:-1], path[1:]):
            hop_latency += G[u][v]["latency"]
            energy += cfg["tx_cost_mJ"]
        lat_ov, e_ov = s2.overheads(first_packet=first_packet)
        hop_latency += lat_ov
        energy += e_ov
        first_packet = False  # handshake modeled once

        delivered += 1
        latencies.append(hop_latency)
        total_energy += energy

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
        "avg_latency_ms": round(mean(latencies), 2),
        "energy_mJ_total": round(total_energy, 2),
        "total_msgs": delivered,
        "intercepted": intercepted,
        "eav_detect_rate": round(100.0 * detections / max(1, delivered), 2)
    }
    return logs, summary

if __name__ == "__main__":
    cfg_path = ROOT / "config" / "sim_config.yaml"
    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)
    logs, summary = run_secure(cfg)
    save_logs(logs, str(ROOT / "results" / "logs_secure.csv"))
    save_summary(summary, str(ROOT / "results" / "summary_secure.csv"))
    print(summary)
