import time
from typing import List, Tuple

def generate_messages(cfg: dict, start: float | None = None) -> List[Tuple[str, str, float, float]]:
    """
    Create messages: (src, dst, size_kB, t_gen)
    devA -> devB periodic traffic
    """
    t0 = time.time() if start is None else start
    msgs = []
    for i in range(cfg["messages"]):
        msgs.append(("devA", "devB", cfg["message_size_kB"], t0 + i * cfg["period_s"]))
    return msgs
