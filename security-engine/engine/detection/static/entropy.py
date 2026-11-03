"""
Shannon Entropy Calculator & Obfuscation Detector
Calculates information entropy for files and string segments.
"""

import math
from typing import List, Dict, Tuple, Optional
from collections import Counter

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory

# Shannon entropy thresholds
HIGH_ENTROPY_FILE_THRESHOLD = 5.9      # Packed / encrypted file
HIGH_ENTROPY_STRING_THRESHOLD = 5.4    # Base64 / Hex packed literal
MIN_STRING_LENGTH_FOR_ENTROPY = 40     # Ignore short variable names or strings


def calculate_shannon_entropy(data: bytes | str) -> float:
    """
    Computes Shannon entropy: H = -sum(p_i * log2(p_i)).
    Returns float in range [0.0, 8.0] for bytes, or [0.0, log2(alphabet_size)] for strings.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")

    total_len = len(data)
    if total_len == 0:
        return 0.0

    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p_i = count / total_len
        entropy -= p_i * math.log2(p_i)

    return round(entropy, 3)


class EntropyAnalyzer:
    """
    Scans files and string candidates for high-entropy obfuscation.
    Never elevates beyond MEDIUM on entropy alone.
    """

    def analyze_file(self, file_path: str, rel_path: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        try:
            with open(file_path, "rb") as f:
                content = f.read(512 * 1024)  # Read up to 512 KB
        except OSError:
            return findings

        if not content:
            return findings

        # Skip binaries (ELF, PE, images, etc.) which legitimately have high entropy
        if content.startswith((b"\x7fELF", b"MZ", b"PK\x03\x04", b"\x1f\x8b")):
            return findings

        # Calculate whole-file entropy
        file_entropy = calculate_shannon_entropy(content)

        if file_entropy >= HIGH_ENTROPY_FILE_THRESHOLD and len(content) > 1024:
            findings.append(SecurityFinding(
                module="ENTROPY_ANALYZER",
                rule_id="OBFUSCATION_HIGH_ENTROPY_FILE",
                category=FindingCategory.OBFUSCATION,
                severity=Severity.MEDIUM,  # Explicitly capped per architecture constraints
                confidence=0.75,
                title="High-Entropy File Content (Possible Packing/Obfuscation)",
                description=(
                    f"File exhibits abnormally high Shannon entropy ({file_entropy:.2f} bits/byte). "
                    "This pattern frequently correlates with encrypted payloads, packed strings, or minified code."
                ),
                affected_file=rel_path,
                evidence={
                    "entropy": file_entropy,
                    "threshold": HIGH_ENTROPY_FILE_THRESHOLD,
                    "sample_size_bytes": len(content),
                },
                detection_method="SHANNON_ENTROPY",
            ))

        return findings

