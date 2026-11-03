from fastapi import FastAPI

app = FastAPI(
    title="PkgSentinel Sandbox Controller",
    description="Dedicated Sandbox Detonation Orchestrator",
    version="0.1.0"
)


@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "pkgsentinel-sandbox-controller",
        "phase": "Phase 2 Target"
    }

