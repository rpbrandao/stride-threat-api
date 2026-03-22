"""
app/main.py
FastAPI application entry point.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import analysis, categories
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"🚀 STRIDE Threat Analysis API starting — env={settings.APP_ENV}")
    yield
    print("👋 Shutting down")


app = FastAPI(
    title="STRIDE Threat Analysis API",
    description=(
        "API that receives architecture diagrams and generates automated "
        "threat analysis using the STRIDE methodology powered by Azure OpenAI GPT-4 Vision."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────
app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(categories.router, prefix="/api/v1", tags=["Reference"])


# ── Health ───────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "version": "1.0.0", "env": settings.APP_ENV}


# ── Root ─────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse({
        "message": "STRIDE Threat Analysis API",
        "docs": "/docs",
        "health": "/health",
    })
