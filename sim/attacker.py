# sim/attacker.py
import random
from typing import Iterable, Optional, Tuple, List, Dict, Any

class Attacker:
    """
    Passive eavesdropper supporting:
      - placement: "gateway", "global", or list of edge tuples (('devA','gw'), ...)
      - success_prob: float (or dict for per-link overrides)
      - rng_seed for reproducibility
    It also supports lightweight logging of observations.
    """

    def __init__(self, placement="gateway", success_prob=1.0, rng_seed: Optional[int]=None, logger=None):
        self.placement = placement
        self.rng = random.Random(rng_seed)
        # store per-link/per-node probabilities optionally
        if isinstance(success_prob, dict):
            self.success_prob_map = success_prob
            self.default_p = 0.0
        else:
            self.success_prob_map = {}
            self.default_p = float(success_prob)
        self.logger = logger  # optional callable to record events

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
        probs: List[float] = []
        # check per-edge overrides if user provided a dict
        pairs = list(zip(path[:-1], path[1:]))
        for edge in pairs:
            if edge in self.success_prob_map:
                probs.append(self.success_prob_map[edge])
            elif (edge[1], edge[0]) in self.success_prob_map:
                probs.append(self.success_prob_map[(edge[1], edge[0])])
        # node override (gateway)
        if "gw" in path and "gw" in self.success_prob_map:
            probs.append(self.success_prob_map["gw"])
        probs.append(self.default_p)
        return max(probs) if probs else 0.0

    def try_intercept(self, path: Iterable[str]) -> bool:
        """
        Return True if attacker observes and succeeds in intercepting this path.
        Also logs observation if logger is provided: logger(dict).
        """
        observed = self._observes_path(path)
        p = self._success_p(path) if observed else 0.0
        success = self.rng.random() < p if observed else False

        if self.logger is not None:
            info: Dict[str, Any] = {
                "path": "->".join(path),
                "observed": observed,
                "success_prob": p,
                "intercepted": success
            }
            try:
                self.logger(info)
            except Exception:
                pass  # don't break simulation for logging problems

        return success
