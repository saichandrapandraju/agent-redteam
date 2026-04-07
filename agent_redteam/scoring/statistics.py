"""Statistical functions for scoring — confidence intervals and aggregation."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class ConfidenceStats:
    mean: float
    std_dev: float
    ci_lower: float
    ci_upper: float
    sample_size: int


_Z_TABLE = {0.80: 1.282, 0.90: 1.645, 0.95: 1.960, 0.99: 2.576}


def compute_confidence_interval(
    outcomes: list[float],
    confidence_level: float = 0.90,
) -> ConfidenceStats:
    """Compute confidence interval for a proportion using Wilson score interval.

    More accurate than normal approximation for small n and extreme proportions.
    """
    n = len(outcomes)
    if n == 0:
        return ConfidenceStats(0.0, 0.0, 0.0, 1.0, 0)

    p_hat = sum(outcomes) / n

    if n == 1:
        return ConfidenceStats(p_hat, 0.0, 0.0, 1.0, 1)

    std_dev = math.sqrt(p_hat * (1 - p_hat) / n)

    z = _Z_TABLE.get(confidence_level, 1.645)
    denominator = 1 + z**2 / n
    center = (p_hat + z**2 / (2 * n)) / denominator
    margin = (z / denominator) * math.sqrt(
        p_hat * (1 - p_hat) / n + z**2 / (4 * n**2)
    )

    ci_lower = max(0.0, center - margin)
    ci_upper = min(1.0, center + margin)

    return ConfidenceStats(
        mean=p_hat,
        std_dev=std_dev,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        sample_size=n,
    )
