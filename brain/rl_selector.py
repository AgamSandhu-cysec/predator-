"""
brain/rl_selector.py

Thompson Sampling exploit selector.

For each exploit we maintain a Beta distribution:
    Beta(alpha=success_count + 1, beta=failure_count + 1)

When selecting from a candidate list we sample once from each distribution
and rank by the sample value.  This naturally:
  - Favours exploits with high historic success (exploitation)
  - Still gives low-count / unknown exploits occasional top slots (exploration)

As data accumulates, the Beta distributions concentrate around the true
success rate and the selector becomes increasingly confident.
"""
import numpy as np
from utils.logger import get_logger
logger = get_logger('RLSelector')

class ThompsonSamplingSelector:
    """
    Reorders exploit candidates using Thompson Sampling from Beta distributions.

    Usage
    -----
    selector = ThompsonSamplingSelector(feedback_logger)
    ordered  = selector.select(candidates)          # highest sampled p first
    """

    def __init__(self, feedback_logger):
        self._db = feedback_logger

    def select(self, candidates: list, seed: int | None=None) -> list:
        """
        Reorder *candidates* by Thompson-sampled success probability.

        Parameters
        ----------
        candidates : list of exploit dicts (must have 'exploit' or 'module' key)
        seed       : optional RNG seed for reproducibility in tests

        Returns
        -------
        Same dicts reordered — highest sampled probability first.
        Each dict gets 'thompson_sample' key added for transparency.
        """
        if not candidates:
            return candidates
        rng = np.random.default_rng(seed)
        counts = self._db.get_thompson_counts()
        scored: list = []
        for rec in candidates:
            name = rec.get('exploit') or rec.get('module', '')
            s, f = counts.get(name, (0, 0))
            alpha = s + 1
            beta = f + 1
            sample = float(rng.beta(alpha, beta))
            scored.append((rec, sample))
            logger.debug(f'  Thompson: {name} Beta({alpha},{beta}) → sample={sample:.3f}')
        scored.sort(key=lambda x: -x[1])
        result = []
        for rec, sample in scored:
            r = dict(rec)
            r['thompson_sample'] = round(sample, 3)
            result.append(r)
        return result

    def get_success_rates(self) -> dict:
        """
        Return Laplace-smoothed success rate per exploit for UI display.
        """
        counts = self._db.get_thompson_counts()
        return {name: round((s + 1) / (s + f + 2), 3) for name, (s, f) in counts.items()}
