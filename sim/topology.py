import networkx as nx

def build_topology(cfg: dict) -> nx.Graph:
    """
    Build a tiny IoT graph with two devices and a gateway.
    System 1 forces routing via the gateway (no direct P2P link).
    """
    G = nx.Graph()
    G.add_node("devA", role="device", pos=(0.0, 0.0), mips=1000, battery=5000)
    G.add_node("devB", role="device", pos=(20.0, 0.0), mips=1000, battery=5000)
    G.add_node("gw",   role="gateway", pos=(10.0, 0.0), mips=4000, battery=20000)

    G.add_edge("devA", "gw", latency=cfg["latency_dev_gw_ms"], bw=10)
    G.add_edge("devB", "gw", latency=cfg["latency_gw_dev_ms"], bw=10)

    # For System 1 (vulnerable), default = false (no direct link)
    if cfg.get("allow_direct_link", False):
        G.add_edge("devA", "devB", latency=8, bw=10)

    return G
