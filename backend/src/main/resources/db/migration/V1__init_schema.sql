-- ====================================================================
-- PkgSentinel Database Schema v2.1
-- ====================================================================

-- 1. Packages Catalog Table
CREATE TABLE IF NOT EXISTS packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem VARCHAR(32) NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_analyzed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_packages_ecosystem_name UNIQUE (ecosystem, name)
);

CREATE INDEX IF NOT EXISTS idx_packages_lookup ON packages (ecosystem, name);

-- 2. Publishers Table
CREATE TABLE IF NOT EXISTS publishers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem VARCHAR(32) NOT NULL,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    is_flagged BOOLEAN NOT NULL DEFAULT FALSE,
    account_created_at TIMESTAMP WITH TIME ZONE,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_publishers_ecosystem_user UNIQUE (ecosystem, username)
);

-- 3. Package Versions Table
CREATE TABLE IF NOT EXISTS package_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id UUID NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version_string VARCHAR(128) NOT NULL,
    sha256_hash VARCHAR(64),
    tarball_url TEXT,
    release_date TIMESTAMP WITH TIME ZONE,
    registry_metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_package_version UNIQUE (package_id, version_string)
);

CREATE INDEX IF NOT EXISTS idx_package_versions_hash ON package_versions (sha256_hash);

-- 4. Scan Jobs Table (Authoritatively owned by Spring Boot)
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_version_id UUID REFERENCES package_versions(id) ON DELETE CASCADE,
    ecosystem VARCHAR(32) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(128) NOT NULL,
    scan_depth VARCHAR(32) NOT NULL DEFAULT 'FAST',
    status VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
    triggered_by VARCHAR(64) NOT NULL DEFAULT 'API',
    retry_count INT NOT NULL DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    failure_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs (status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_pkg ON scan_jobs (ecosystem, package_name, package_version);

-- 5. Scan Results Table
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    verdict VARCHAR(32) NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL,
    confidence_score NUMERIC(4, 3) NOT NULL,
    summary_notes TEXT,
    mitre_tactics JSONB,
    analyzed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_scan_results_job UNIQUE (scan_job_id)
);

-- 6. Module Findings Table
CREATE TABLE IF NOT EXISTS module_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    module_name VARCHAR(64) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 1.0,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    file_path TEXT,
    line_number INT,
    code_snippet TEXT,
    telemetry_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_module_findings_result ON module_findings (scan_result_id);

-- 7. Threat Indicators Table
CREATE TABLE IF NOT EXISTS threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_finding_id UUID REFERENCES module_findings(id) ON DELETE CASCADE,
    indicator_type VARCHAR(64) NOT NULL,
    indicator_value TEXT NOT NULL,
    is_confirmed_c2 BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_val ON threat_indicators (indicator_type, indicator_value);
