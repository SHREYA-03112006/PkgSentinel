# PkgSentinel — Build Round 1 Live Demo Guide

This guide provides the complete live demonstration script and presentation walkthrough for **Hackathon Build Round 1**.

---

## 1. Value Proposition (The 30-Second Elevator Pitch)

> *"Traditional vulnerability scanners only catch known CVEs—leaving developers vulnerable to zero-day malicious packages that appear on npm and PyPI minutes before being installed. **PkgSentinel** stops software supply-chain attacks before execution. Using AST-level code hazard detection, publisher timeline forensics, and length-bounded typosquatting analysis, PkgSentinel evaluates package behavior and produces explainable security verdicts in real time."*

---

## 2. Ideal Live Demo Walkthrough (90 Seconds)

### Step 1: Platform Overview (`/`)
1. **Navigate to the Overview**:
   - Point out the **top bar status**: `Engine: Online` (connected to Spring Boot, Redis Streams, and PostgreSQL).
   - Point out the **4 key metric cards**:
     - **Total Scans**
     - **Threats Detected** (Malicious packages intercepted)
     - **Safe Packages** (Verified clean)
     - **Suspicious Packages** (Flagged for review)
   - Highlight the **Risk Profile Breakdown bar** showing the live proportion of safe vs. malicious packages.
   - Note the **Recent Scans table**: Clean, uncluttered, displaying real persisted data.

### Step 2: The Package Scanner (`/scan`)
1. **Click "Scan Package"** in the sidebar:
   - Notice the **minimal, distraction-free interface**: No wall of text, just target coordinates and registry toggle (`npm` / `PyPI`).
2. **Choose a Demo Scenario**:
   - **Scenario A: Clean Popular Package (SAFE)**
     - Click the preset `express@4.19.2` or `chalk@5.3.0`.
   - **Scenario B: Zero-Day Typosquat / Malicious Artifact (MALICIOUS/SUSPICIOUS)**
     - Click the preset `requests-fake@1.0.0` or enter a target package.
3. **Click "Analyze Package"**:
   - Show the **active progress tracker**:
     - `1. Queued in Redis` (Transactional outbox dispatch)
     - `2. AST Analysis` (Safe decompression & Python/JS AST inspection)
     - `3. Persisted` (Persisted in PostgreSQL)
   - Emphasize that this is **real asynchronous orchestration**, not simulated frontend timeouts.

### Step 3: Inspect the Security Report
1. Once completed, the interface transitions directly to the **Security Report**:
   - **Top Scorecard**: Large prominent Risk Score (e.g. `85 / 100`) and clear Verdict Pill (`MALICIOUS` / `SUSPICIOUS` / `SAFE`).
   - **Verdict Attribution**: Bullet points detailing exactly why the engine reached this decision (e.g., *Typosquatting proximity to popular PyPI package 'requests'*, *Obfuscated Buffer/eval execution*).
   - **Analysis Coverage**: Pills showing completed heuristic modules (AST, Metadata, Typosquatting, Shannon Entropy).
   - **Severity Counts**: Critical, High, Medium, Low breakdown.
2. **Expand a Finding**:
   - Click on any finding row to reveal the **forensic detail drawer**:
     - Plain-English explanation.
     - Affected file and line number.
     - Exact **evidence code snippet** or distance metric.
     - Detection module and confidence score.
   - Emphasize: *"Unlike black-box scanners, every PkgSentinel finding is directly traceable to package code and metadata."*

### Step 4: Scan Audit History (`/history`)
1. **Navigate to "Scan History"**:
   - Show the compact, unified forensic log of all past scans.
   - Test the **search filter**: Type a package name (e.g., `requests`) to filter in real time.
   - Test the **verdict filters**: Click `MALICIOUS` or `SAFE` to isolate specific threat levels.
2. **Click any row**:
   - The interface deep-links directly back into the scan's detailed security report (`/scan?jobId=<UUID>`).

---

## 3. Demo Cheat-Sheet: Preset Packages

| Package | Ecosystem | Expected Verdict | Why It Triggers |
| :--- | :--- | :--- | :--- |
| `chalk@5.3.0` | npm | `SAFE` (0/100) | Clean AST, valid metadata, no evasive APIs. |
| `express@4.19.2` | npm | `SAFE` (0/100) | Verified maintainer, no obfuscation, canonical name. |
| `requests-fake@1.0.0` | PyPI | `SUSPICIOUS` / `MALICIOUS` | Damerau-Levenshtein proximity to `requests`, suspicious naming. |

---

## 4. Architecture Verification Quick Reference

If judges ask about the underlying system:
- **Backend**: Java 21 + Spring Boot 3.3.4 (REST API, Outbox Pattern, PostgreSQL persistence).
- **Security Engine**: Python 3.11+ (FastAPI, AST visitor engines, Esprima JS parser, Shannon entropy, safe TarSlip/ZipSlip decompression).
- **Transport**: Redis Streams (`stream:scan-jobs`) with consumer groups, lease heartbeats (30s TTL), and dead-letter queue.
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS (responsive, zero-fluff minimal SaaS design).

