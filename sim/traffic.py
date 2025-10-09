from typing import List, Tuple

def generate_messages(cfg: dict) -> List[Tuple[str, str, int, float]]:
    """
    Produce (src, dst, size_kB, tgen) for a single flow devA->devB.
    Pulls values from cfg['traffic'].
    """
    tcfg = cfg.get("traffic", {})
    n = int(tcfg.get("num_messages", 300))
    size_kB = int(tcfg.get("size_kB", 1))
    return [("devA", "devB", size_kB, float(i)) for i in range(n)]
