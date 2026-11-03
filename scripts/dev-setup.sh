#!/usr/bin/env bash
# ==============================================================================
# PkgSentinel — Developer Environment Bootstrap
# ==============================================================================
set -e

echo "[+] Initializing PkgSentinel Development Environment..."

# 1. Environment Config
if [ ! -f .env ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env
fi

# 2. Python Security Engine Virtualenv
echo "[*] Setting up Python virtual environment..."
cd security-engine
if [ ! -d ".venv" ]; then
    python -m venv .venv
fi
source .venv/bin/activate
pip install -e ".[dev]"
cd ..

# 3. Frontend Dependencies
echo "[*] Installing Frontend dependencies..."
cd frontend
npm install
cd ..

echo "[✓] PkgSentinel local setup complete!"
echo "    - Run infrastructure: docker compose up -d postgres redis"
echo "    - Run backend: cd backend && ./mvnw spring-boot:run"
echo "    - Run engine: cd security-engine && uvicorn engine.main:app --reload"
echo "    - Run frontend: cd frontend && npm run dev"
