"""
Shannon Entropy Calculator & Obfuscation Detector
Calculates information entropy for files and string segments.
"""

import math
import os
import re
from typing import List, Dict, Tuple, Optional, Set
from collections import Counter

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory

# Shannon entropy thresholds
HIGH_ENTROPY_FILE_THRESHOLD = 5.9      # Packed / encrypted file
HIGH_ENTROPY_STRING_THRESHOLD = 5.4    # Base64 / Hex packed literal
MIN_STRING_LENGTH_FOR_ENTROPY = 120    # Minimum length for embedded string entropy check

EXCLUDED_METADATA_DIRS = (
    ".dist-info",
    ".egg-info",
    "node_modules",
    ".git",
    "__pycache__",
)

EXCLUDED_FILENAMES = {
    "record",
    "metadata",
    "wheel",
    "pkg-info",
    "sources.txt",
    "top_level.txt",
    "entry_points.txt",
    "installed-files.txt",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "license",
    "license.txt",
    "copying",
    "notice",
    "authors",
    "changelog",
    "changelog.md",
    "changelog.rst",
    "readme",
    "readme.md",
    "readme.rst",
    "readme.txt",
}

EXCLUDED_EXTENSIONS = {
    ".txt", ".md", ".rst", ".json", ".yaml", ".yml", ".toml",
    ".csv", ".tsv", ".map", ".svg", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".sum", ".sha256", ".sha512", ".md5", ".sig", ".asc",
}

CODE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts",
    ".sh", ".bash", ".bat", ".cmd", ".ps1", ".vbs",
    ".php", ".rb", ".pl",
}

TEST_OR_DOCS_PATH_PATTERN = re.compile(
    r"(^|[/\\])(tests?|fixtures?|examples?|samples?|demos?|benchmarks?|docs?)[/\\]|(^|[/\\])test_[^/\\]+\.py$|(^|[/\\])[^/\\]+_test\.py$|(^|[/\\])conftest\.py$",
    re.IGNORECASE,
)

# Regex to extract string literals from source code
STRING_LITERAL_REGEX = re.compile(r"""(?:["']{1,3})([^"'\r\n]{120,})(?:["']{1,3})""")


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

        normalized_path = rel_path.replace("\\", "/").lower()
        filename = os.path.basename(normalized_path)
        name_without_ext, ext = os.path.splitext(filename)

        # 1. Skip standard packaging and metadata directories
        for d in EXCLUDED_METADATA_DIRS:
            if f"/{d}/" in f"/{normalized_path}/" or normalized_path.startswith(f"{d}/") or f".{d}" in normalized_path:
                return findings

        # 2. Skip known packaging, license, and manifest filenames
        if filename in EXCLUDED_FILENAMES or name_without_ext in EXCLUDED_FILENAMES:
            return findings

        # 3. Skip documentation, manifests, hashes, and asset extensions
        if ext in EXCLUDED_EXTENSIONS:
            return findings

        # 4. Only inspect code/script files or non-extension script files
        if ext and ext not in CODE_EXTENSIONS:
            return findings

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
        is_test = bool(TEST_OR_DOCS_PATH_PATTERN.search(normalized_path))

        if file_entropy >= HIGH_ENTROPY_FILE_THRESHOLD and len(content) > 1024:
            findings.append(SecurityFinding(
                module="ENTROPY_ANALYZER",
                rule_id="OBFUSCATION_HIGH_ENTROPY_FILE",
                category=FindingCategory.OBFUSCATION,
                severity=Severity.LOW if is_test else Severity.MEDIUM,
                confidence=0.40 if is_test else 0.75,
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
                    "context": "TEST_OR_FIXTURE" if is_test else "PROD",
                },
                detection_method="SHANNON_ENTROPY",
            ))

        # Check for embedded high-entropy string literals in production code files (exclude test data)
        if ext in CODE_EXTENSIONS and len(findings) == 0 and not is_test:
            try:
                text_content = content.decode("utf-8", errors="ignore")
                for match in STRING_LITERAL_REGEX.finditer(text_content):
                    literal = match.group(1)
                    str_entropy = calculate_shannon_entropy(literal)
                    if str_entropy >= HIGH_ENTROPY_STRING_THRESHOLD:
                        findings.append(SecurityFinding(
                            module="ENTROPY_ANALYZER",
                            rule_id="OBFUSCATION_HIGH_ENTROPY_STRING",
                            category=FindingCategory.OBFUSCATION,
                            severity=Severity.MEDIUM,
                            confidence=0.70,
                            title="High-Entropy Embedded String Literal",
                            description=(
                                f"Source code contains high-entropy string literal ({str_entropy:.2f} bits/byte, "
                                f"length {len(literal)}). Often indicates packed bytecode, shellcode, or encoded payload."
                            ),
                            affected_file=rel_path,
                            evidence={
                                "entropy": str_entropy,
                                "threshold": HIGH_ENTROPY_STRING_THRESHOLD,
                                "literal_length": len(literal),
                                "literal_prefix": literal[:40],
                            },
                            detection_method="SHANNON_ENTROPY_STRING",
                        ))
                        break  # One high-entropy string finding per file is sufficient
            except Exception:
                pass

        return findings
