# PkgSentinel — Secure Package Ingestion & Archive Analysis Pipeline

This document details the architecture, cryptographic verification, SSRF defenses, extraction safeguards, and inventory mechanics implemented in **Phase 1B**.

---

## 1. Pipeline Architecture

```
[ PackageCoordinates (Ecosystem, Name, Version) ]
                       |
                       v
         [ Layer 1 & 2 Coordinate Validation ]
                       |
                       v
       [ Official Registry Metadata Resolution ]
          - npm: https://registry.npmjs.org/@scope%2Fpkg
          - PyPI: https://pypi.org/pypi/{pkg}/json
                       |
                       v
         [ Registry Allowlist & Anti-SSRF Check ]
          - DNS IP Resolution & Loopback/Private IP Filtering
          - IP Pinning & Hostname SNI Preservation
          - Disabled Environment Proxies
                       |
                       v
            [ Streaming Chunk Download ]
          - Enforces Maximum Quota (100 MB)
          - Atomic Temp File Finalization
                       |
                       v
      [ Cryptographic Integrity Verification ]
          - SRI (sha512 / sha384 / sha256)
          - SHA-256 Hex Digest (PyPI)
          - SHA-1 Shasum (npm legacy fallback)
                       |
                       v
         [ Safe Archive Extraction ]
          - TarSlip & ZipSlip Traversal Guard
          - Decompression Bomb Ratio & File Count Guard
          - Special File Rejection (FIFOs, Device Nodes, Symlinks)
          - File Permission Masking (0o644 / 0o755)
                       |
                       v
         [ Deterministic File Inventory ]
          - Alphabetical Sorting
          - File Magic Typing & Null-byte Binary Detection
          - Extension Distribution & Suspicious Indicators (.pth, .node, .exe)
                       |
                       v
             [ IngestionResult ]
```

---

## 2. Ingestion Modules & Responsibilities

| Module | File | Core Security Function |
|---|---|---|
| **Models & Errors** | `engine/ingestion/models.py` | Defines structured schemas (`PackageCoordinates`, `ResolvedDistribution`, `FileInventoryItem`, `IngestionResult`) and explicit exception hierarchy. |
| **Integrity Verifier** | `engine/ingestion/integrity.py` | Constant-time cryptographic verification (`hmac.compare_digest`) supporting Subresource Integrity (SRI) base64 strings and 64-char hex SHA-256 digests. |
| **Registry Client** | `engine/ingestion/registry_client.py` | Strict coordinate regex validation, official host allowlisting (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`), and DNS resolution filtering against RFC 1918, loopback, link-local, and Carrier-Grade NAT IPs. |
| **Registry Downloader** | `engine/ingestion/registry_downloader.py` | Streams archives with 100 MB cap, rejects unexpected redirects, disables environment proxies (`trust_env=False`), applies connect/read timeouts, and cleans up partial downloads on error. |
| **Archive Extractor** | `engine/ingestion/archive_extractor.py` | Securely unpacks `.tgz`, `.tar.gz`, `.whl`, and `.zip` archives. Enforces NFKC unicode normalization, commonpath root containment, and bomb ratio checks. |
| **Package Inventory** | `engine/ingestion/inventory.py` | Generates deterministic, alphabetically ordered file inventories with magic byte typing, null-byte binary detection, and suspicious filename flags (`.pth`, `.node`, `.exe`, `.env`). |
| **Pipeline Coordinator** | `engine/ingestion/pipeline.py` | Glues ingestion phases together inside an isolated temporary session workspace and guarantees cleanup of failed or discarded workspaces. |

---

## 3. Configurable Limits & Safe Defaults

| Limit Metric | Default Setting | Purpose |
|---|---|---|
| **Max Compressed Download Size** | `100 MB` | Prevents disk and bandwidth exhaustion during streaming downloads. |
| **Max Total Extracted Bytes** | `150 MB` | Caps uncompressed workspace size to thwart multi-file decompression bombs. |
| **Max Single File Size** | `50 MB` | Prevents a single oversized file from consuming memory/disk. |
| **Max File Count** | `2,500` | Defends against inode exhaustion and traversal denial-of-service. |
| **Max Compression Ratio** | `50:1` | Aborts decompression if ratio exceeds 50x after 5 MB decompressed. |
| **Max Path Length** | `255 chars` | Prevents filesystem buffer overflow and Windows MAX_PATH errors. |

---

## 4. Special Filesystem Safeguards

1. **Path Traversal (ZipSlip / TarSlip)**:
   Every archive entry path is normalized with Unicode NFKC, stripped of Windows drive letters (`C:`) and UNC network paths (`\\server\share`), and verified with `os.path.commonpath([abs_root, resolved_dest]) == abs_root`.
2. **Disallowed Entries**:
   - Device Nodes (Character & Block) $\rightarrow$ Rejected (`ArchiveSpecialFileError`).
   - FIFOs (Named Pipes) $\rightarrow$ Rejected (`ArchiveSpecialFileError`).
   - Hard Links $\rightarrow$ Rejected (`ArchiveSpecialFileError`).
   - Symbolic Links $\rightarrow$ Disallowed to prevent symlink race conditions and directory escape attacks (`ArchiveSpecialFileError`).
3. **Permission Masking**:
   Archive entries are created with explicit, non-executable permissions (`0o644` for files, `0o755` for directories), stripping arbitrary setuid/setgid and executable bits.

---

## 5. Running the Test Suite

```bash
# Run complete test suite in security-engine
cd security-engine
python -m pytest

# Run with verbose output
python -m pytest -v
```

---

## 6. Known Limitations & Next Steps

1. **Dynamic Sandboxing**: Phase 1B covers safe static archive ingestion and file inventory. Execution of package installation scripts is intentionally deferred to Phase 2 (Sandbox Controller & Canary).
2. **Large Package Quotas**: Legitimate machine learning libraries (e.g. `torch`, `tensorflow`) exceed 150 MB and will be rejected by default limits. Tiered whitelist quotas will be configured in future enterprise policies.
