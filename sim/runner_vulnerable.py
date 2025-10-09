import yaml
import networkx as nx
from statistics import mean
from pathlib import Path

from topology import build_topology
from traffic import generate_messages
from attacker import Attacker
from security_none import security_overhead_ms, is_sniffable
from utils import save_logs, save_summary

ROOT = Path(__file__).resolve().parents[1]

def run(cfg: dict):
    G = build_topology(cfg)
    msgs = generate_messages(cfg)

    # attacker from config
    att_cfg = cfg.get("attacker", {"placement":"gateway","success_prob":1.0,"rng_seed":42})
    att = Attacker(
        placement=att_cfg.get("placement","gateway"),
        success_prob=att_cfg.get("success_prob",1.0),
        rng_seed=att_cfg.get("rng_seed", None)
    )

    logs = []
    delivered = 0
    caught = 0
    latencies = []
    total_energy = 0.0

    for (src, dst, size_kB, tgen) in msgs:
        # Force routing via gateway (max exposure)
        path = nx.shortest_path(G, src, "gw") + nx.shortest_path(G, "gw", dst)[1:]

        # link latency + simple energy model
        hop_latency = 0
        energy = 0.0
        for u, v in zip(path[:-1], path[1:]):
            hop_latency += G[u][v]["latency"]
            energy += cfg["tx_cost_mJ"]

        # no security overheads in System 1
        hop_latency += security_overhead_ms()
        energy += cfg["cpu_cost_mJ"] * 0

        # eavesdropping decision (attacker)
        was_intercepted = att.try_intercept(path) if is_sniffable() else False
        if was_intercepted:
            caught += 1

        delivered += 1
        latencies.append(hop_latency)
        total_energy += energy

        logs.append({
            "src": src, "dst": dst,
            "path": "->".join(path),
            "latency_ms": hop_latency,
            "energy_mJ": energy,
            "intercepted": was_intercepted
        })

    confidentiality = 100.0 * (1 - (caught / max(1, delivered)))
    summary = {
        "scenario": "System1_Vulnerable",
        "confidentiality_pct": round(confidentiality, 2),
        "avg_latency_ms": round(mean(latencies), 2),
        "energy_mJ_total": round(total_energy, 2),
        "total_msgs": delivered,
        "intercepted": caught
    }
    return logs, summary

if __name__ == "__main__":
    cfg_path = ROOT / "config" / "sim_config.yaml"
    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)

    logs, summary = run(cfg)
    save_logs(logs, str(ROOT / "results" / "logs_vulnerable.csv"))
    save_summary(summary, str(ROOT / "results" / "summary_vulnerable.csv"))
    print(summary)
