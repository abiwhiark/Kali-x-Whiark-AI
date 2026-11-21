"""
Kali AI - Backend Application
FastAPI server for the cybersecurity agent.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database.db import init_db
from backend.api.routes import router as api_router
from backend.core.config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    settings = get_settings()
    logger.info("=" * 60)
    logger.info("  Kali x Whiark AI (Chatbot: Kali AI) — Starting up")
    logger.info("  Demo mode: %s", settings.demo_mode)
    logger.info("  Gemini model: %s", settings.GEMINI_MODEL)
    logger.info("=" * 60)
    await init_db()
    logger.info("Database initialized.")
    yield
    logger.info("Kali x Whiark AI — Shutting down")


app = FastAPI(
    title="Kali x Whiark AI",
    description="Autonomous Cybersecurity Operator (Chatbot: Kali AI)",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS — allow the React frontend during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router)
