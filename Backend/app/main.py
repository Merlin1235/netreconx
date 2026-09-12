from fastapi import FastAPI


app = FastAPI(
    title="NetReconX API",
    description=(
        "Authorized network security assessment and "
        "reconnaissance platform API."
    ),
    version="0.1.0",
)


@app.get("/api/v1/health")
def health_check() -> dict[str, str]:
    """Return API health information."""

    return {
        "status": "healthy",
        "service": "netreconx-api",
    }
