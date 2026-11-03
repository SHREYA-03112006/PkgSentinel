# PkgSentinel — Build Round 1 Implementation Report

This report summarizes the design refinements, architecture integrations, and verification results completed for **Hackathon Build Round 1**.

---

## 1. Executive Summary

In Build Round 1, the user interface and presentation layer of PkgSentinel were overhauled to align with a **minimal, premium cybersecurity SaaS design system**. Visual clutter, excessive descriptive text, and decorative artifacts were eliminated in favor of high-impact typography, real-time backend telemetry, and compact forensic data representations.

All user interactions connect directly to the existing Spring Boot orchestrator, PostgreSQL database, Redis Streams transport, and Python security engine. **Zero mock data or simulated responses were introduced.**

---

## 2. Key Refinements Implemented

### A. Minimal Design System
- **Palette**: Dark navy / near-black background (`#090d16`), slate card backgrounds (`#0f172a`), subtle borders (`#1e293b`), and cyan accents (`#06b6d4`).
- **Semantic Threat Colors**:
  - `MALICIOUS`: `#ef4444` (Rose/Red)
  - `SUSPICIOUS`: `#f59e0b` (Amber)
  - `SAFE`: `#10b981` (Emerald/Green)
- **Hierarchy & Whitespace**: Replaced multi-paragraph descriptions with large monospace metrics, compact status indicators, and clean tabular layouts.

### B. Navigation & Shell (`Sidebar.tsx` & `Header.tsx`)
- **Streamlined Navigation**: Stripped unimplemented placeholder routes (`/lockfile`, `/settings`). The navigation strictly features:
  1. `Overview` (`/`)
  2. `Scan Package` (`/scan`)
  3. `Scan History` (`/history`)
- **Top Bar Telemetry**:
  - Dynamic page title reflection.
  - Live backend health checking (`GET /api/v1/health`), reflecting `Engine: Online` or `Degraded`.
  - Storage connectivity status (`PostgreSQL + Redis`).

### C. Dashboard Overview (`DashboardPage.tsx`)
- **4 Authoritative Metric Cards**:
  - `Total Scans`: Total recorded scans from PostgreSQL.
  - `Threats Detected`: Count of `MALICIOUS` verdicts.
  - `Safe Packages`: Count of `SAFE` verdicts.
  - `Suspicious Packages`: Count of `SUSPICIOUS` verdicts.
- **Risk Profile Breakdown**: Compact horizontal proportion bar showing Safe vs. Suspicious vs. Malicious ratio.
- **Recent Scans Table**: Clean tabular feed with clickable row navigation to reports.
- **Recent Security Findings**: Flagged zero-day indicators aggregated across analyzed packages.
- **Honest Empty State**: When no scans exist, displays a clean call-to-action without fabricated placeholders.

### D. Package Scanner & Presets (`SingleScanPage.tsx`)
- **Clean Inputs**: Toggle for `npm` / `PyPI`, monospace package name and version fields.
- **Quick Demo Presets**: One-click preset chips for `chalk@5.3.0`, `express@4.19.2`, `requests@2.31.0`, and `requests-fake@1.0.0`.
- **Asynchronous Progress Tracker**: Displays active state machine stages (`QUEUED` $\to$ `PROCESSING` $\to$ `COMPLETED`).
- **Duplicate Prevention**: Form submission disabled while scan is in flight.

### E. Compact Security Report (`SingleScanPage.tsx`)
- **Header Scorecard**: Large prominent Risk Score (`X / 100`) and clear Verdict Pill (`SAFE`, `SUSPICIOUS`, `MALICIOUS`).
- **Severity Breakdown**: Counts of Critical, High, Medium, and Low findings.
- **Verdict Attribution**: Bulleted attribution points explaining the exact rationale behind the verdict.
- **Expandable Evidence Drawers**: Collapsed by default; expands to reveal affected file path, line number, detection module, confidence percentage, and raw code snippet.

### F. Scan Audit History (`HistoryPage.tsx`)
- **Unified Forensic Table**:
  - Columns: `Registry`, `Package`, `Version`, `Risk Score`, `Verdict`, `Scanned Date`, `Report`.
- **Multi-Axis Real-Time Filters**:
  - Live text search across package name and Job ID.
  - Registry filter (`ALL`, `NPM`, `PYPI`).
  - Verdict filter (`ALL`, `SAFE`, `SUSPICIOUS`, `MALICIOUS`).
- **Clickable Deep-Linking**: Clicking any row or "Inspect" navigates directly to the target report.

---

## 3. Verification & Build Status

| Component | Status | Notes |
| :--- | :--- | :--- |
| **Frontend Production Build** | **PASSED** | Built with `vite v5.4.21` and `tsc` in 8.46s with **0 errors**. |
| **Security Engine Tests** | **PASSED** | **73 of 73 tests passing** across ingestion, AST detection, typosquatting, scoring, and queue consumer. |
| **Backend Integration** | **PRESERVED** | REST controllers (`/api/v1/scans`, `/api/v1/health`), Outbox pattern, and internal callback endpoints untouched and fully compatible. |

---

## 4. Runtime Constraints & Verification Details

- **Database / Docker Sandbox**:
  - Spring Boot and PostgreSQL/Redis run via Docker Compose (`infrastructure/docker/docker-compose.yml`).
  - The frontend proxies `/api` to `http://localhost:8080`.
  - When backend services are stopped, the frontend handles offline states gracefully with clear network alerts.
- **Security Boundaries**:
  - Package code is never executed on the host. Ingestion occurs inside isolated sandboxed workers.
  - Callbacks require `X-Internal-Token` authentication.
