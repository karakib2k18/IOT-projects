import random

def intercepted(success_prob: float) -> bool:
    """Bernoulli trial for whether a sniffed packet is compromised."""
    return random.random() < success_prob
