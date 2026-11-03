# PkgSentinel — Architecture v2.1 Working Baseline

This document summarizes the approved baseline architecture for PkgSentinel, implemented in Phase 1A.

## Technology Stack
- **Backend Orchestrator**: Java 21, Spring Boot 3.3.4, Maven, Flyway, Spring Data JPA, Spring Data Redis.
- **Security Engine**: Python 3.11+, FastAPI, Pydantic V2, pytest.
- **Frontend Cockpit**: React 18, TypeScript, Vite, Tailwind CSS, Lucide icons, React Router DOM.
- **Data Persistence**: PostgreSQL 16 (authoritative state store owned by Spring Boot).
- **Asynchronous Queue & Cache**: Redis 7 (Redis Streams for job dispatching).
- **Isolation Sandbox**: Dedicated Python Sandbox Controller with rootless Docker / gVisor runtime (Phase 2).

## Core Principles Enforced in Phase 1A
1. **Single State Ownership**: Spring Boot is the sole authoritative owner of PostgreSQL scan state (`packages`, `package_versions`, `scan_jobs`, `scan_results`, `module_findings`). Python workers never write directly to PostgreSQL.
2. **Safe Decoupled Sandbox**: Python workers have no Docker socket access.
3. **Decoupled Scoring & Verdicts**: Continuous numerical risk score ($0.0 - 100.0$) and categorical verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`) with explicit override rules for verified critical exploits.
4. **Defense-in-Depth SSRF Protection**: Spring Boot Layer 1 identifier validation & URL construction; Python Worker Layer 2 IP-pinning, private range rejection, and checksum verification.
