import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.detection.ml import load_model
from app.api.routes import pages_router, analysis_router, health_router, history_router, report_router, auth_router


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(ROOT_DIR, "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm ML model into memory on startup
    try:
        load_model()
        print("[Startup] QR Quishing ML model pre-loaded successfully.")
    except Exception as exc:
        print(f"[Startup Warning] Could not pre-load ML model: {exc}")
    yield


app = FastAPI(
    title="QR Quishing Inspector API",
    description=(
        "A cybersecurity intelligence system for detecting malicious QR Phishing "
        "(Quishing) attacks using hybrid rule-based heuristics and machine learning."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Register routers
app.include_router(pages_router)
app.include_router(analysis_router)
app.include_router(health_router)
app.include_router(history_router)
app.include_router(report_router)
app.include_router(auth_router)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
