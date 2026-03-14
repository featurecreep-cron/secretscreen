"""Shannon entropy detection for machine-generated strings.

Layer 5 (aggressive mode only): catches secrets that don't match any
key pattern or known format by detecting high-randomness values.

Shannon entropy measures information density in bits per character.
Human-written strings: typically 1.9-3.9 bits/char.
Machine-generated secrets: typically 4.5+ bits/char.

Only non-whitespace characters are counted — spaces, tabs, and newlines
are stripped before calculation.
"""

from __future__ import annotations

import math
from collections import Counter

# Minimum entropy (bits/char) to flag a value as potentially machine-generated.
DEFAULT_ENTROPY_THRESHOLD = 4.5

# Minimum length of the non-whitespace portion to evaluate.
# Short strings have unreliable entropy measurements.
MIN_ENTROPY_LENGTH = 20


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character.

    Whitespace is stripped before calculation.
    Returns 0.0 for empty strings.
    """
    # Strip all whitespace — spaces aren't informative for secret detection
    chars = "".join(value.split())
    length = len(chars)

    if length == 0:
        return 0.0

    counts = Counter(chars)
    entropy = 0.0
    for count in counts.values():
        freq = count / length
        entropy -= freq * math.log2(freq)

    return entropy


def looks_like_secret(
    value: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    min_length: int = MIN_ENTROPY_LENGTH,
) -> float | None:
    """Check if a value has high enough entropy to be a machine-generated secret.

    Returns the entropy value if it exceeds the threshold, or None.
    """
    chars = "".join(value.split())
    if len(chars) < min_length:
        return None

    ent = shannon_entropy(value)
    if ent >= threshold:
        return ent

    return None
