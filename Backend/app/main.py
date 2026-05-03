from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import logging

from Backend.app.agent.long_term_memory import LongTermMemory
from Backend.app.agent.langchain_decision_engine import LangChainDecisionEngine
from Backend.app.core.model_registry import ModelRegistry
from Backend.app.core.policy_loader import PolicyLoader

from Backend.app.api.predict import router as predict_router
from Backend.app.api.ingest import router as ingest_router
from Backend.app.api.metrics import router as metrics_router
from Backend.app.api.evaluation import router as evaluation_router
from Backend.app.api.websocket import router as ws_router
from Backend.app.api.auth import router as auth_router

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinel")

# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="The Sentinel — Agentic AI Cyber Defense System",
    version="3.0.0",
    description=(
        "Real-time intrusion detection with LangChain "
        "autonomous agentic response"
    ),
)

# ── CORS ──────────────────────────────────────────────────────
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "*"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allow_headers=["*"],
)


# ── Startup ───────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 55)
    logger.info("  THE SENTINEL v3.0 — LANGCHAIN AGENT STARTUP")
    logger.info("=" * 55)

    # ── Policy ──
    policy_path = Path(__file__).resolve().parent / "policies" / "policy_v1.json"
    policy = PolicyLoader(policy_path)
    logger.info(f"[POLICY] Version: {policy.get_version()}")

    # ── Long-term memory (MongoDB) ──
    try:
        app.state.long_term_memory = LongTermMemory()
        logger.info("[MEMORY] MongoDB connected")
    except Exception as e:
        logger.error(f"[MEMORY] MongoDB failed: {e}")
        app.state.long_term_memory = None

    # ── Model registry ──
    try:
        ModelRegistry.preload_all()
        logger.info("[MODELS] All models preloaded")
    except Exception as e:
        logger.error(f"[MODELS] Preload failed: {e}")
        raise RuntimeError(f"Cannot start without models: {e}")

    # ── LangChain Agent ──
    MODEL_ACCURACY = ModelRegistry.get_model_accuracy()

    logger.info("[AGENT] Initializing LangChain ReAct agent...")
    logger.info("[AGENT] This may take 5-10 seconds on first startup...")

    app.state.agent = LangChainDecisionEngine(
        model_accuracy   = MODEL_ACCURACY,
        thresholds       = policy.get_thresholds(),
        weights          = policy.get_weights(),
        governance_rules = policy.get_governance_rules(),
    )

    if app.state.agent.is_agent_ready():
        info = app.state.agent.get_agent_info()
        logger.info("[AGENT] LangChain agent ready")
        logger.info(f"[AGENT] LLM: {info['llm']}")
        logger.info(f"[AGENT] Tools: {info['tools']}")
    else:
        logger.warning("[AGENT] LangChain agent failed — using rule-based fallback")

    logger.info("[STARTUP] The Sentinel v3.0 is online")
    logger.info("=" * 55)


# ── Shutdown ──────────────────────────────────────────────────
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("[SHUTDOWN] The Sentinel is shutting down")


# ── Routers ───────────────────────────────────────────────────
app.include_router(predict_router,    prefix="/predict",    tags=["Prediction"])
app.include_router(ingest_router,     prefix="/ingest",     tags=["Ingestion"])
app.include_router(metrics_router,    prefix="/metrics",    tags=["Metrics"])
app.include_router(evaluation_router, prefix="/evaluation", tags=["Evaluation"])
app.include_router(ws_router,                               tags=["WebSocket"])
app.include_router(auth_router,       prefix="/auth",        tags=["Auth"])


# ── Health ────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {
        "status":  "online",
        "system":  "The Sentinel — Agentic AI Cyber Defense",
        "version": "3.0.0",
    }


@app.get("/health", tags=["Health"])
def health():
    agent_info = {}
    if hasattr(app.state, "agent"):
        try:
            agent_info = app.state.agent.get_agent_info()
        except Exception:
            agent_info = {"ready": False}

    return {
        "status":  "healthy",
        "agent":   "initialized" if hasattr(app.state, "agent") else "not ready",
        "memory":  "connected" if app.state.long_term_memory else "unavailable",
        "models":  ModelRegistry.available_models(),
        "langchain_agent": agent_info,
    }


@app.get("/agent/info", tags=["Agent"])
def agent_info():
    """Returns full LangChain agent configuration and status."""
    if not hasattr(app.state, "agent"):
        return {"error": "Agent not initialized"}
    return app.state.agent.get_agent_info()