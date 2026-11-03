import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class EngineSettings(BaseSettings):
    """Configuration for PkgSentinel Python Security Engine."""
    app_name: str = "pkgsentinel-security-engine"
    environment: str = "development"
    debug: bool = True
    port: int = 8000

    # Redis Stream Configuration
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    scan_stream_key: str = "stream:scan-jobs"
    dlq_stream_key: str = "stream:scan-jobs:dlq"
    consumer_group: str = "engine-workers"
    consumer_name: str = "worker-1"

    # Internal Authentication Shared Token
    internal_auth_secret: str = "sentinel-internal-secure-token-2026"

    # Backend Orchestrator Callback URL
    backend_callback_url: str = "http://localhost:8080/internal/v1/scans"

    # Ephemeral Workspace Path
    ephemeral_workspace_dir: str = "/tmp/pkgsentinel/workspaces"

    model_config = SettingsConfigDict(
        env_prefix="SECURITY_ENGINE_",
        env_file=".env",
        extra="ignore"
    )


settings = EngineSettings()
