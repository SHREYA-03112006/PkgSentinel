# PkgSentinel — Asynchronous Scan Orchestration & End-to-End Integration (Phase 1D)

This document specifies the implementation of the reliable asynchronous package scanning pipeline connecting the Spring Boot backend, Redis Streams transport, Python security analysis workers, and the React frontend dashboard.

---

## 1. Architectural Architecture & Component Roles

```
                                  +----------------------------+
                                  |       React Frontend       |
                                  +--------------+-------------+
                                      ^          | 
              GET /api/v1/scans/{id}  |          | POST /api/v1/scans
                     (Polling 1.5s)   |          v
                           +----------+----------+----------+
                           |   Spring Boot Orchestrator     |
                           |   (Authoritative Lifecycle)    |
                           +----+---------------+-----------+
                                |               ^
           Atomic ACID Write    |               | Authenticated Callback
     (ScanJob + OutboxEvent)    |               | (POST /internal/v1/scans/{id}/callback
                                v               |  Header: X-Internal-Token)
                     +----------+----+          |
                     | PostgreSQL DB |          |
                     +---------------+          |
                            ^                   |
           Poll Pending     |                   |
           Outbox Events    |                   |
                     +------+--------+          |
                     | Outbox Pub    |          |
                     | Service       |          |
                     +------+--------+          |
                            | XADD              |
                            v                   |
               +------------+------------+      |
               |  Redis Streams Transport|      |
               |  (stream:scan-jobs)     |      |
               +------------+------------+      |
                            | XREADGROUP        |
                            v                   |
               +------------+------------+      |
               | Python Security Worker  +------+
               | - Lease Heartbeat (30s) |
               | - Safe Ingestion (1B)   |
               | - AST Detection (1C)    |
               | - Worker Recovery / DLQ |
               +-------------------------+
```

### Role Separation & Trust Boundaries
1. **Spring Boot (Sole State Owner)**:
   - Only component authorized to alter persistent scan lifecycle state in PostgreSQL.
   - Maintains transactional consistency using the **Transactional Outbox Pattern**.
   - Authenticates worker callbacks via shared high-entropy secret (`X-Internal-Token`).
   - Idempotently accepts callbacks: if duplicate callbacks arrive, returns HTTP 200 without duplicate records.

2. **Redis Streams (`stream:scan-jobs` & `stream:scan-jobs:dlq`)**:
   - High-throughput task transport buffer with consumer groups (`engine-workers`).
   - Dead letter queue routes poison-pill or repeatedly failed packages after 3 delivery attempts.

3. **Python Security Worker (`ScanJobWorker`)**:
   - Zero PostgreSQL access; consumes strictly from Redis Streams.
   - Runs safe ingestion (Phase 1B) and heuristic AST detection (Phase 1C).
   - Manages a 30s renewable lease with 10s heartbeats (`job:{jobId}:lease`) to prevent false-reclaim by peer workers.
   - Acknowledges (`XACK`) messages **only after Spring Boot accepts the callback with HTTP 200**.

4. **React Frontend**:
   - Submits scan jobs to `POST /api/v1/scans`.
   - Polls `GET /api/v1/scans/{jobId}` every 1.5s with lifecycle phase tracking.
   - Renders genuine empty states, live metric calculations, and comprehensive verdict report summaries.

---

## 2. Scan Lifecycle State Machine

```
              [ Client POST /api/v1/scans ]
                           │
                           ▼
                      ┌─────────┐
                      │ QUEUED  │  (ScanJob + OutboxEvent saved in PostgreSQL)
                      └────┬────┘
                           │ OutboxPublisher publishes to Redis Streams
                           │ Worker consumes message & begins execution
                           ▼
                    ┌────────────┐
                    │ PROCESSING │  (Safe archive unpack & AST detection)
                    └─────┬──────┘
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
  ┌───────────┐                     ┌────────────┐
  │ COMPLETED │                     │   FAILED   │
  └───────────┘                     └────────────┘
(Report, Verdict, Findings       (Failure reason persisted;
 persisted in PostgreSQL)         message dead-lettered or acked)
```

---

## 3. Reliability & Failure Handling

| Failure Scenario | Mitigation Strategy | Result |
| :--- | :--- | :--- |
| **Backend crashes after job creation** | Outbox pattern writes `ScanJob` and `OutboxEvent` in same DB transaction. | On backend restart, pending outbox events are published to Redis. |
| **Worker crashes midway through scan** | Lease key (`job:{jobId}:lease`) expires after 30s without heartbeat. | Peer worker detects expired message via `XPENDING_RANGE`, claims it via `XCLAIM`, and resumes execution. |
| **Poison pill package (crashes worker $\ge$ 3 times)** | Delivery count tracked in Redis PEL (`times_delivered`). | Once delivery count reaches 3, message is routed to `stream:scan-jobs:dlq` and acked from active stream. |
| **Network partition during callback delivery** | Worker receives non-200 or connection error; does NOT call `XACK`. | Message remains in consumer group PEL for automatic retry upon network restoration. |
| **Duplicate callback delivery** | Spring Boot validates current job status. | If already `COMPLETED` or `FAILED`, returns HTTP 200 idempotently without re-inserting findings. |

---

## 4. Test Verification Summary

The complete test suite verifies the end-to-end integration:

- **Security Engine (`pytest`)**:
  - `tests/test_queue_consumer.py`: 6 tests passing (lease management, malformed message drops, success callback, HTTP callback failure retention, ingestion failure callbacks, DLQ routing after 3 retries).
  - Total Security Engine tests: **73 passed in 3.97s**.
- **Frontend Dashboard (`vite build`)**:
  - Production bundle built cleanly with zero TypeScript errors.
