import networkx as nx

def build_topology(cfg: dict) -> nx.Graph:
    """
    Simple 3-node topology: devA -- gw -- devB, plus optional direct link.
    Latencies:
      devA<->gw = 10 ms
      gw<->devB = 10 ms
      devA<->devB = 8 ms (shortest for System-2 direct P2P)
    """
    G = nx.Graph()
    G.add_node("devA", role="device", pos=(0.0, 0.0), mips=1000, battery=5000)
    G.add_node("gw",   role="gateway", pos=(10.0, 0.0), mips=4000, battery=20000)
    G.add_node("devB", role="device", pos=(20.0, 0.0), mips=1000, battery=5000)

    G.add_edge("devA", "gw", latency=10)
    G.add_edge("gw",   "devB", latency=10)
    # direct link exists (used in System-2). System-1 runner forces gw path anyway.
    G.add_edge("devA", "devB", latency=8)
    return G
