"""
Deterministic file inventory generator with file typing, binary heuristics, and suspicious file indicators.
"""

import os
import hashlib
from typing import List, Dict
from engine.ingestion.models import FileInventoryItem, PackageInventory

# Extensions associated with executable or native code
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".pyd", ".node",
    ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".ps1"
}

# Suspicious specific filenames
SUSPICIOUS_FILENAMES = {
    ".env", ".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"
}


def detect_file_type_and_binary(file_path: str) -> tuple[str, bool]:
    """
    Inspects magic header bytes (up to 1024 bytes) to classify file type
    and determine whether the file is binary or text.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(1024)
    except OSError:
        return "UNKNOWN", False

    if not header:
        return "EMPTY", False

    # 1. Binary Magic Headers
    if header.startswith(b"\x7fELF"):
        return "ELF_BINARY", True
    if header.startswith(b"MZ"):
        return "PE_WINDOWS_BINARY", True
    if header.startswith(b"\xca\xfe\xba\xbe") or header.startswith(b"\xcf\xfa\xed\xfe"):
        return "MACH_O_BINARY", True
    if header.startswith(b"PK\x03\x04"):
        return "ZIP_ARCHIVE", True
    if header.startswith(b"\x1f\x8b"):
        return "GZIP_COMPRESSED", True

    # 2. Text magic / shebang
    if header.startswith(b"#!"):
        return "SHELL_SCRIPT", False

    # 3. Check for binary null byte heuristic
    is_binary = b"\x00" in header

    # Classify common text formats
    ext = os.path.splitext(file_path)[1].lower()
    if not is_binary:
        if ext in (".js", ".mjs", ".cjs"):
            return "JAVASCRIPT", False
        if ext in (".ts", ".tsx"):
            return "TYPESCRIPT", False
        if ext == ".py":
            return "PYTHON", False
        if ext == ".json":
            return "JSON", False
        if ext in (".md", ".markdown", ".rst"):
            return "DOCUMENTATION", False
        if ext in (".yaml", ".yml"):
            return "YAML", False
        return "TEXT", False

    return "GENERIC_BINARY", True


def check_suspicious_filename(rel_path: str) -> bool:
    """
    Checks if a relative file path matches suspicious criteria:
    - Suspicious binary / script extension
    - Double extension (e.g. package.js.exe)
    - Python .pth startup execution hooks
    - Secret files (.env, credentials)
    """
    base = os.path.basename(rel_path).lower()
    name_parts = base.split(".")

    # 1. Exact match on sensitive filenames
    if base in SUSPICIOUS_FILENAMES or base.startswith(".env."):
        return True

    # 2. Python .pth hook (runs code on interpreter startup)
    if base.endswith(".pth"):
        return True

    # 3. Double extension (e.g. app.js.exe or logo.png.bat)
    if len(name_parts) >= 3:
        penultimate = f".{name_parts[-2]}"
        last = f".{name_parts[-1]}"
        if penultimate in (".js", ".py", ".png", ".jpg", ".txt") and last in SUSPICIOUS_EXTENSIONS:
            return True

    # 4. Dangerous executable extensions
    ext = os.path.splitext(base)[1]
    if ext in SUSPICIOUS_EXTENSIONS:
        return True

    return False


def build_package_inventory(workspace_dir: str) -> PackageInventory:
    """
    Traverses the extracted package workspace, calculates cryptographic digests,
    and returns a deterministic, alphabetically sorted inventory.
    """
    abs_workspace = os.path.abspath(workspace_dir)
    items: List[FileInventoryItem] = []
    ext_dist: Dict[str, int] = {}
    binary_count = 0
    suspicious_files: List[str] = []
    total_bytes = 0

    for root, _, filenames in os.walk(abs_workspace):
        for fname in filenames:
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, abs_workspace).replace("\\", "/")

            try:
                st = os.stat(abs_path)
            except OSError:
                continue

            file_size = st.st_size
            total_bytes += file_size

            # Compute SHA-256
            hasher = hashlib.sha256()
            with open(abs_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
            file_sha256 = hasher.hexdigest()

            # File extension
            ext = os.path.splitext(fname)[1].lower().lstrip(".")
            ext_key = ext if ext else "no_ext"
            ext_dist[ext_key] = ext_dist.get(ext_key, 0) + 1

            # Type and binary check
            file_type, is_binary = detect_file_type_and_binary(abs_path)
            if is_binary:
                binary_count += 1

            # Executable metadata check (POSIX permissions or binary type)
            is_exec = (st.st_mode & 0o111) != 0 or file_type in ("ELF_BINARY", "PE_WINDOWS_BINARY", "MACH_O_BINARY")

            if check_suspicious_filename(rel_path):
                suspicious_files.append(rel_path)

            items.append(FileInventoryItem(
                relative_path=rel_path,
                size_bytes=file_size,
                sha256=file_sha256,
                extension=ext,
                file_type=file_type,
                is_binary=is_binary,
                is_executable=is_exec,
            ))

    # Sort items deterministically by relative path
    items.sort(key=lambda x: x.relative_path)
    suspicious_files.sort()

    return PackageInventory(
        total_files=len(items),
        total_bytes=total_bytes,
        extension_distribution=dict(sorted(ext_dist.items())),
        binary_file_count=binary_count,
        suspicious_files=suspicious_files,
        files=items,
    )
