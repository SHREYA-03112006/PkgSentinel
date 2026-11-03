-- ====================================================================
-- PkgSentinel Database Migration V2: Transactional Outbox & Callback Schema
-- ====================================================================

-- 1. Transactional Outbox Events Table
CREATE TABLE IF NOT EXISTS outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload TEXT NOT NULL,
    published BOOLEAN NOT NULL DEFAULT FALSE,
    retry_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox_events (published, created_at) WHERE published = FALSE;

-- 2. Extend scan_results with coverage and raw_score fields
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS raw_score NUMERIC(5, 2) DEFAULT 0.00;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS analysis_coverage JSONB;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS verdict_reasons JSONB;
