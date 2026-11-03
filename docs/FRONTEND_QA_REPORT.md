# PkgSentinel — Frontend QA & UX Audit Report

**Date:** 2026-11-03  
**Status:** All Audits Passed (Production Ready)  
**Target Applications:** React 18 / TypeScript / Vite 5 / Tailwind CSS / Framer Motion

---

## 1. Audit Scope & Objectives

The goal of this audit was to inspect and verify every screen, component, and interaction in the unified PkgSentinel frontend, ensuring that the pastel glassmorphism aesthetic provided by the team lead operates reliably with the real Spring Boot backend and Python AST detection engine.

### Core Testing Pillars:
1. **Design System Fidelity:** Consistent application of `#FAF8F5`, soft lavender, powder, mint, and blush pastels without harsh dark-theme clashes.
2. **Component Completeness:** Zero dead buttons, broken links, or stubbed static text where real interactions are expected.
3. **Authentication Flows:** Comprehensive Sign In, Sign Up, validation feedback, password strength indicators, and session persistence.
4. **Scanner & Progress Telemetry:** Real-time feedback through Redis Outbox, AST Heuristics, and Report Finalization states.
5. **Scan Result Presentation:** Accurate rendering of verdicts (`ALLOW`, `WARN`, `BLOCK`), SVG risk score gauge, expandable code snippets, and structured zero-day recommendations.
6. **Audit History & Filtering:** Search by package name / UUID, filter by ecosystem (`npm`, `PyPI`), filter by decision, and empty states.
7. **Cross-Device Responsiveness:** Mobile navbar drawer, wrap-around chips, and responsive grids.

---

## 2. Component-by-Component QA Assessment

### 2.1 Navigation Bar (`Navbar.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Sticky glass header with `backdrop-blur-md` and soft bottom border.
  - Brand identity with zero-day shield badge (`Zero-Day Shield`).
  - Active tab highlighting with bottom pill indicator.
  - Live backend health indicator (`Engine Online` / `Engine Degraded` / `Engine Offline`) polling `/api/v1/health` every 30 seconds.
  - Quick action button (`Scan Package`) smooth-scrolling to the scanner section.
  - User profile badge with initials, username, and role dropdown.
  - Mobile hamburger menu drawer with full navigation, auth controls, and responsive layout.

### 2.2 Hero Section (`Hero.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Pastel ambient gradient blobs with CSS blur (`-z-10`).
  - Bold headline and concise zero-day positioning statement ("Your Guardian Against Malicious Packages").
  - Interactive demonstration package preset chips:
    - `requests-fake` (PyPI Typosquatting demo -> `BLOCK`)
    - `chalk` (npm AST heuristic demo -> `WARN`)
    - `requests` (PyPI Clean demo -> `ALLOW`)
    - `express` (npm Clean demo -> `ALLOW`)
  - Clicking any chip automatically populates the scanner input and selects the ecosystem.

### 2.3 Package Vulnerability Scanner (`Scanner.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Ecosystem tab toggle (`npm` vs `PyPI`).
  - Package coordinate text input with search icon.
  - Optional version input defaulting to `latest`.
  - Asynchronous submission to Spring Boot orchestrator outbox (`POST /api/v1/scans`).
  - Real-time 3-stage progress stepper:
    1. `Redis Outbox` (Job queued)
    2. `AST Heuristics` (Python worker processing)
    3. `Report Finalized` (PostgreSQL saved)
  - Inline error banner for missing inputs, backend errors, or offline engine state.

### 2.4 Forensic Scan Result (`ScanResult.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Clean animated entrance via Framer Motion.
  - Dynamic pastel color coding by verdict:
    - `ALLOW`: Mint (`#22C55E` / `bg-pastel-mint-100`)
    - `WARN`: Powder Blue (`#0EA5E9` / `bg-pastel-powder-100`)
    - `BLOCK`: Blush / Rose (`#F43F5E` / `bg-pastel-blush-100`)
  - Animated SVG circular gauge for numerical risk score (0–100).
  - Verdict reasons callout listing specific triggering heuristics.
  - Findings accordion:
    - Severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
    - Detection method and rule ID.
    - File path and line number coordinates.
    - Toggleable syntax-highlighted code evidence snippet.
    - Concrete remediation recommendation for each finding.
  - "Copy Audit Report" button writing clean ASCII summary to system clipboard.
  - "Scan Another Package" reset trigger.

### 2.5 Recent Scan History & Audit Log (`ScanHistory.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Tabular forensic log pulling from PostgreSQL (`GET /api/v1/scans`).
  - Search filter by package name or UUID.
  - Dropdown filter by ecosystem (`npm`, `PyPI`, `All`).
  - Dropdown filter by verdict decision (`ALLOW`, `WARN`, `BLOCK`, `All`).
  - Clean empty state illustration when 0 packages match criteria.
  - Click-to-inspect interaction loading full historic scan into the result viewer.
  - Asynchronous refresh button with spinning state during fetch.

### 2.6 Authentication Modal (`AuthModal.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Unified pastel glassmorphic dialog with modal blur backdrop.
  - Tab toggle between Sign In and Sign Up.
  - Password visibility toggle (eye icon) on all password fields.
  - Real-time password strength meter evaluating length (8+, 12+), uppercase letters, numeric characters, and symbols.
  - Client-side validation preventing invalid usernames, malformed emails, and password mismatches.
  - Submitting authenticates against Spring Boot backend endpoints and persists token in storage.

### 2.7 About & Zero-Day Paradigm (`About.tsx`)
- **Status:** PASS
- **Features Tested:**
  - Educational deep-dive explaining why traditional CVE scanners fail on newly published packages.
  - 6 heuristic detection capability cards with custom icons and pastel badges.
  - Real backend API specification table documenting Spring Boot endpoints.

---

## 3. Automated Test Results

### 3.1 Frontend Adapter & Validation Tests (`npm test`)
```
> pkgsentinel-frontend@0.1.0 test
> node --test test-adapters.js

✔ mapBackendVerdictToUI maps SAFE to ALLOW (1.3575ms)
✔ mapBackendVerdictToUI maps SUSPICIOUS to WARN (0.2143ms)
✔ mapBackendVerdictToUI maps MALICIOUS to BLOCK (0.1737ms)
✔ mapBackendFindingToUI formats findings and recommendations (0.421ms)
✔ mapBackendReportToUI transforms Spring Boot report to UI model (29.2751ms)
✔ calculatePasswordStrength evaluates length and character sets (0.332ms)
✔ validateRegisterPayload checks required fields and formats (0.2643ms)

ℹ tests 7
ℹ suites 0
ℹ pass 7
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 149.6065
```

### 3.2 Production Bundle Build (`npm run build`)
```
vite v5.4.21 building for production...
✓ 1884 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   1.13 kB │ gzip:   0.64 kB
dist/assets/index-CHm3huVd.css   36.71 kB │ gzip:   6.42 kB
dist/assets/index-C-3xt6Wo.js   345.47 kB │ gzip: 105.12 kB
✓ built in 8.83s
```

### 3.3 Security Engine Tests (`pytest`)
```
============================= 73 passed in 2.93s ==============================
```

---

## 4. Summary of Improvements Delivered

1. **Integrated Real Authentication:** Added database migrations, JPA entities, controller endpoints, and frontend services for true user registration and login—no mock credentials.
2. **Zero-Day Experience Polished:** Provided quick-start preset cards in Hero allowing instant demonstration of typosquatting, AST heuristics, and clean package flows.
3. **Password Security Feedback:** Added real-time strength meter and visibility toggles to eliminate user frustration during account creation.
4. **Session Attribution:** Scans triggered by authenticated users are forensically tagged in PostgreSQL.
5. **Clean Pastel Glassmorphism Maintained:** Ensured full design harmony across all components in accordance with the leader frontend guidelines.
