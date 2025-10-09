import random
from typing import Iterable, Optional, List, Dict, Any

class Attacker:
    """
    Passive eavesdropper observing certain paths/links.
    placement:
      - "gateway": observes any path that includes node "gw"
      - "global" : observes all paths
      - list of edges: e.g., [("devA","gw"), ("gw","devB")]
    success_prob:
      - float in [0,1], or dict for per-edge overrides; default applied otherwise
    """
    def __init__(self, placement="gateway", success_prob=1.0, rng_seed: Optional[int]=None, logger=None):
        self.placement = placement
        self.rng = random.Random(rng_seed)
        self.logger = logger
        if isinstance(success_prob, dict):
            self.success_prob_map = success_prob
            self.default_p = 0.0
        else:
            self.success_prob_map = {}
            self.default_p = float(success_prob)

    def _observes_path(self, path: Iterable[str]) -> bool:
        if self.placement == "global":
            return True
        if self.placement == "gateway":
            return "gw" in path
        if isinstance(self.placement, (list, tuple, set)):
            pairs = set(zip(path[:-1], path[1:]))
            for u, v in self.placement:
                if (u, v) in pairs or (v, u) in pairs:
                    return True
            return False
        return False

    def _success_p(self, path: Iterable[str]) -> float:
        # per-edge overrides, else default
        probs = [self.default_p]
        if isinstance(self.placement, (list, tuple, set)):
            for edge in zip(path[:-1], path[1:]):
                if edge in self.success_prob_map:
                    probs.append(self.success_prob_map[edge])
                elif (edge[1], edge[0]) in self.success_prob_map:
                    probs.append(self.success_prob_map[(edge[1], edge[0])])
        if "gw" in path and "gw" in self.success_prob_map:
            probs.append(self.success_prob_map["gw"])
        return max(probs)

    def try_intercept(self, path: Iterable[str]) -> bool:
        observed = self._observes_path(path)
        p = self._success_p(path) if observed else 0.0
        success = self.rng.random() < p if observed else False
        if self.logger:
            try:
                self.logger({"path": "->".join(path), "observed": observed, "p": p, "intercepted": success})
            except Exception:
                pass
        return success
