# PkgSentinel — Python Security Engine

Autonomous micro-engine responsible for static AST parsing, entropy calculation, YARA rule matching, typosquatting metric evaluation, and canary sandbox coordination.

## Local Setup & Virtual Environment

### 1. Create Virtual Environment
```bash
cd security-engine
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```bash
pip install -e ".[dev]"
```

### 3. Run FastAPI Health Server
```bash
uvicorn engine.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Run Queue Consumer Worker
```bash
python -m engine.core.queue_consumer
```

### 5. Run Test Suite
```bash
pytest
```

