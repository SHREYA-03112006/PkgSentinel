# PkgSentinel — Frontend Merge & Integration Plan

## 1. Overview
This plan defines the end-to-end integration strategy for merging the **leader-provided frontend** (`leader-frontend/PkgSentinel-main/Frontend`) into the **PkgSentinel main repository** (`frontend/`).

The leader's frontend provides the **primary visual design** (pastel glassmorphic design system, Framer Motion animations, comprehensive component hierarchy, radial gauge, and scan history table). The existing PkgSentinel frontend provides **real backend integration, TypeScript typing, asynchronous scan lifecycle polling, and Spring Boot DTO mapping**.

---

## 2. Component & Architecture Comparison

| Dimension | Existing Main Frontend (`frontend/`) | Leader Frontend (`leader-frontend/`) | Target Merged Architecture |
| :--- | :--- | :--- | :--- |
| **Language** | TypeScript (`.tsx`) | JavaScript (`.jsx`) | **TypeScript (`.tsx`)** with strict types |
| **Visual Design** | Dark cyber theme (`#090d16`, cyan/slate) | Light pastel glassmorphism (`#FAF8F5`, lavender, mint, blush) | **Leader's Light Pastel Glassmorphism** |
| **Animation Engine** | Minimal Tailwind CSS transitions | `framer-motion` 11.x | **`framer-motion`** + soft shadows |
| **Backend API Integration** | Real Spring Boot endpoints (`/api/v1/scans`, `/api/v1/health`) | Mocked via `USE_MOCK_DATA = true` in `scanService.js` | **Real Spring Boot Endpoints ONLY** |
| **Scan Execution** | Asynchronous transactional outbox + polling (`QUEUED` $\to$ `PROCESSING` $\to$ `COMPLETED`) | Simulated delay (`setTimeout 1800ms`) + keyword rules | **Real Asynchronous Lifecycle Polling** |
| **Data Models** | `ScanReportResponse`, `FindingItem`, `Verdict` | Custom `KNOWN_SAMPLES` mock dictionary | **Type-safe Adapter Layer (`types/` + `services/`)** |
| **Verdict Representation** | `SAFE`, `SUSPICIOUS`, `MALICIOUS` | `ALLOW`, `WARN`, `BLOCK` | **Bidirectional adapter mapping** (`SAFE` $\leftrightarrow$ `ALLOW`, `SUSPICIOUS` $\leftrightarrow$ `WARN`, `MALICIOUS` $\leftrightarrow$ `BLOCK`) |
| **Scan History** | Real PostgreSQL via `/api/v1/scans?page=0&size=50` | `localStorage` fallback with hardcoded samples | **Real Backend History with empty states** |

---

## 3. Mock Functionality to Eliminate

1. **`USE_MOCK_DATA = true`**: Removed completely. No toggle to fall back to fake responses.
2. **`KNOWN_SAMPLES`**: Removed. No synthetic hardcoded package verdicts (`color-setup-v2`, `discord-token-logger`, etc.).
3. **`INITIAL_HISTORY` in `localStorage`**: Removed. History is fetched live from `GET /api/v1/scans`.
4. **`generateDynamicAnalysis()`**: Removed keyword-based mock analysis function.
5. **Hardcoded Stats in Hero**: Static numbers (`12,480+ Packages Scanned`, `99.4% Detection Rate`) replaced with real metrics computed from backend history.

---

## 4. API Adapter Layer Specifications

The Spring Boot backend exposes:
- `POST /api/v1/scans` (Submit package: `{ ecosystem: "NPM"|"PYPI", name: string, version: string }`)
- `GET /api/v1/scans/{jobId}` (Status check: `ScanReportResponse`)
- `GET /api/v1/scans/{jobId}/report` (Dedicated report)
- `GET /api/v1/scans?page=0&size=50` (Paginated history)
- `GET /api/v1/health` (Backend & storage connectivity status)

### Adapter Mapping:
```
Spring Boot (Backend)               UI Model (Leader Design)
---------------------               ------------------------
Verdict.SAFE                 <--->  ALLOW  (Mint theme)
Verdict.SUSPICIOUS           <--->  WARN   (Powder/Amber theme)
Verdict.MALICIOUS            <--->  BLOCK  (Blush/Red theme)
riskScore (0.0 - 100.0)      <--->  riskScore & classification (LOW, MEDIUM, HIGH)
verdictReasons               <--->  summary / attribution bullets
findings[].codeSnippet       <--->  evidence code drawer
analysisCoverage             <--->  coverage tags (AST, Metadata, Typosquatting, Entropy)
```

---

## 5. Execution Steps

1. **Dependencies**: Add `framer-motion` to `frontend/package.json` and install.
2. **Styling System**: Merge pastel colors, fonts, and glassmorphic shadows into `frontend/tailwind.config.js` and `frontend/src/index.css`.
3. **Data Types & Adapter**: Create `src/types/scan.ts`, `src/services/apiClient.ts`, and `src/services/scanService.ts`.
4. **Component Migration**:
   - `Navbar.tsx`: Pastel theme with live health ping (`/api/v1/health`).
   - `Hero.tsx`: Presets, animated shield, real dynamic stats from backend.
   - `Scanner.tsx`: Real validation, async submission, live polling progress (`QUEUED` $\to$ `PROCESSING` $\to$ `COMPLETED`).
   - `ScanResult.tsx`: Radial risk gauge, ALLOW/WARN/BLOCK verdict, attribution reasons, expandable findings with code snippet evidence.
   - `ScanHistory.tsx`: Live audit log, search, ecosystem and verdict filters, report inspection.
   - `About.tsx`: Explains the 5 Zero-Day heuristic detection pillars and architectural pipeline.
5. **Build & Test Verification**: Verify TypeScript, Vite production build, and unit/integration tests.
