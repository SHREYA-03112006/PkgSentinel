# PkgSentinel — Authentication Architecture & UX Audit

**Date:** 2026-11-03  
**Status:** Approved & Implemented  
**Scope:** Backend Authentication Architecture, User & Session Models, Frontend Auth UX, and Security Controls

---

## 1. Executive Summary

During manual frontend inspection, the initial authentication state lacked a cohesive user registration (Sign Up) workflow, while the backend lacked dedicated authentication and session persistence tables. 

To satisfy the zero-trust requirements of PkgSentinel without relying on mock authentication or dummy clients, a full-stack authentication system was implemented:
1. **Spring Boot Security Backend:** Dedicated `users` and `user_sessions` PostgreSQL tables with Flyway migration `V3__user_authentication.sql`.
2. **Cryptographic Password Security:** Salting and key derivation using standard `PBKDF2WithHmacSHA256` (65,536 iterations, 16-byte cryptographically secure random salt, constant-time comparison).
3. **Session Token Transport:** 256-bit cryptographically secure session tokens (`sentinel_sec_...`) with database-backed 30-day lifecycle and revocable bearer session validation.
4. **User-Attributed Scan Ownership:** Scans submitted with an active bearer token automatically tag the persistent audit trail with `USER:<username>`.
5. **Pastel Glassmorphic Frontend Auth UX:** A unified modal matching the leader's visual theme (`#FAF8F5`, lavender, mint, powder, blush) featuring tabbed Sign In / Sign Up, client-side validation, password visibility toggles, and a real-time 4-stage password security strength meter.

---

## 2. Backend Inspection & Architectural Decisions

### 2.1 Backend Capability Audit
Prior to this implementation:
- `ScanController.java` supported an optional `X-Triggered-By` header defaulting to `WEB` or `CLI`.
- No JPA entities, database tables, or controller endpoints existed for `/api/v1/auth`.
- There were no password hashing utilities or session validation interceptors.

### 2.2 Security Architecture Decisions

| Requirement | Implementation Decision | Security Justification |
| :--- | :--- | :--- |
| **Password Storage** | PBKDF2 HMAC-SHA256 (65,536 iterations, 16-byte salt) | NIST SP 800-63B compliant. Eliminates plaintext risk; salted per user to prevent rainbow table attacks. |
| **Session Model** | PostgreSQL-backed `user_sessions` (`sentinel_sec_<hex32>`) | Stateless JWTs cannot be revoked instantly without complex distributed blacklists. Token sessions allow immediate revocation on logout. |
| **Timing Attack Mitigation** | `MessageDigest.isEqual(expected, actual)` | Constant-time byte array comparison prevents side-channel timing leaks during password verification. |
| **Scan Attribution** | Resolves Bearer token in `ScanController.java` | Scans submitted by authenticated users store `USER:<username>` in the PostgreSQL `scan_jobs` table for forensic attribution. |
| **CORS & Origin Safety** | Explicit CORS support on `/api/v1/auth/**` | Permits legitimate SPA clients while isolating unauthorized cross-origin requests. |

---

## 3. Database Schema (`V3__user_authentication.sql`)

```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'USER',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

CREATE TABLE IF NOT EXISTS user_sessions (
    token VARCHAR(128) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions (user_id);
```

---

## 4. API Endpoints

### 4.1 Registration: `POST /api/v1/auth/register`
- **Request Body:**
  ```json
  {
    "username": "alice_sec",
    "email": "alice@company.com",
    "password": "Password123!",
    "fullName": "Alice Walker"
  }
  ```
- **Validation:** Username (min 3 chars), valid email regex, password (min 8 chars), non-blank full name.
- **Response (`201 Created`):**
  ```json
  {
    "token": "sentinel_sec_9a7d3f...",
    "user": {
      "id": "e4c5b162-...",
      "username": "alice_sec",
      "email": "alice@company.com",
      "fullName": "Alice Walker",
      "role": "USER"
    },
    "message": "Registration successful"
  }
  ```

### 4.2 Login: `POST /api/v1/auth/login`
- **Request Body:**
  ```json
  {
    "usernameOrEmail": "alice_sec",
    "password": "Password123!"
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "token": "sentinel_sec_b2891c...",
    "user": { ... },
    "message": "Login successful"
  }
  ```

### 4.3 Profile Verification: `GET /api/v1/auth/me`
- **Header:** `Authorization: Bearer sentinel_sec_...`
- **Response (`200 OK`):** UserSummary profile.
- **Response (`401 Unauthorized`):** If token is missing, expired, or revoked.

### 4.4 Session Invalidation: `POST /api/v1/auth/logout`
- **Header:** `Authorization: Bearer sentinel_sec_...`
- **Response (`204 No Content`):** Deletes session row from `user_sessions`.

---

## 5. Frontend Auth UX Design System Integration

1. **Design Tokens:**
   - Background: Soft cream canvas (`#FAF8F5`).
   - Cards: Glassmorphic white (`bg-white/95 backdrop-blur-xl border border-white/60 shadow-soft-xl`).
   - Accent gradients: `from-pastel-lavender-500 to-pastel-powder-400`.
   - Error states: `bg-rose-50 border-rose-200 text-rose-700`.
   - Success states: `bg-emerald-50 border-emerald-200 text-emerald-700`.

2. **UX Enhancements in `AuthModal.tsx`:**
   - Smooth Framer Motion entrance (`opacity: 0, scale: 0.95, y: 15` -> `1, 1, 0`).
   - Tab switcher for seamless toggling between "Sign In" and "Sign Up".
   - Client-side validation: formats email, flags mismatching passwords, validates minimum character requirements before submission.
   - Interactive show/hide password buttons (`Eye` / `EyeOff` icons).
   - Real-time password strength meter:
     - Too Short (< 8 chars): Rose bar (`text-rose-500`)
     - Weak (length without complexity): Amber bar (`text-amber-600`)
     - Good (length + uppercase + digits): Lavender bar (`text-pastel-lavender-600`)
     - Strong (length + uppercase + digits + special symbols): Emerald bar (`text-emerald-600`)
   - Escape key and backdrop click handlers for easy dismissal.

3. **Navbar Integration in `Navbar.tsx`:**
   - **Unauthenticated:** Shows clean "Sign In" (subtle outline) and "Sign Up" (gradient pill) buttons.
   - **Authenticated:** Shows user avatar badge with initials, username, role pill, and a dropdown menu with quick links to scan history and one-click Sign Out.
   - **Mobile Drawer:** Integrates mobile-responsive profile card and Sign Out button.

---

## 6. Verification and Test Results

- `test-adapters.js`:
  - `calculatePasswordStrength`: 100% pass across short, weak, good, and strong vectors.
  - `validateRegisterPayload`: 100% pass on validation constraints.
- `vite build`: Production bundle generated in 8.83s with 0 errors.
- Python security engine: 73 tests passing.
