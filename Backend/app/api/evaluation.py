import logging
import os
from collections import Counter
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel

load_dotenv()
logger = logging.getLogger("sentinel.evaluation")
router = APIRouter()


class SwitchModelRequest(BaseModel):
    provider: str


@router.post("/switch-model")
def switch_model(body: SwitchModelRequest, request: Request):
    """
    Hot-swap the LangChain LLM provider at runtime.
    Called when the user saves AI Core settings in the frontend.
    """
    agent = getattr(request.app.state, "agent", None)
    if agent is None:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    if not hasattr(agent, "switch_model"):
        raise HTTPException(status_code=501, detail="Agent does not support hot-swap")

    try:
        info = agent.switch_model(body.provider)
        return {
            "status": "switched",
            "provider": info["provider"],
            "model": info["model"],
            "ready": info["ready"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Switch failed: {e}")
        raise HTTPException(status_code=500, detail=f"Switch failed: {e}")


@router.get("/summary")
def evaluation_summary(request: Request):
    """
    Returns an aggregate summary of all agent decisions stored in MongoDB.
    Used by the dashboard for the bento stats grid.
    """
    ltm = request.app.state.long_term_memory
    if ltm is None:
        raise HTTPException(
            status_code=503,
            detail="Long-term memory unavailable — MongoDB not connected"
        )
    
    try:
        # Get all records to aggregate in-memory (small enough for now)
        records = list(ltm.collection.find({}))
        total = len(records)
        
        if total == 0:
            return {
                "total_requests": 0,
                "total_decisions": 0,
                "unique_ips": 0,
                "attack_block_rate": 0,
                "block_rate": 0,
                "avg_confidence": 0,
                "decision_distribution": {},
                "model_distribution": {},
                "top_attack_types": []
            }
            
        # FIX: The field in MongoDB is 'decision', not 'action'
        actions = Counter([r.get("decision") for r in records])
        models  = Counter([r.get("model", "unknown") for r in records])
        ips     = {r.get("srcip") for r in records if r.get("srcip")}
        
        # Only count attacks that were blocked
        attacks = Counter([r.get("attack_type", "Unknown") for r in records if r.get("decision") == "BLOCK"])
        
        confidences = [r.get("confidence", 0) for r in records if "confidence" in r]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0
        
        block_count = actions.get("BLOCK", 0)
        
        return {
            "total_requests": total,
            "total_decisions": total,
            "unique_ips": len(ips),
            "attack_block_rate": round(block_count / total, 3) if total > 0 else 0,
            "block_rate": round((block_count / total) * 100, 1) if total > 0 else 0,
            "avg_confidence": round(avg_conf * 100, 1),
            "decision_distribution": dict(actions),
            "model_distribution": dict(models),
            "top_attack_types": [ {"name": k, "count": v} for k, v in attacks.most_common(5) ]
        }
    except Exception as e:
        logger.error(f"[Evaluation] Summary failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/memory/active")
def get_active_memory(request: Request):
    """
    Returns the current short-term memory (IP summaries) from the LangChain agent.
    Used by logs.html to display behavior analysis.
    """
    engine = getattr(request.app.state, "agent", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="LangChain agent not initialized")
    
    return {
        "status": "success",
        "ip_summaries": engine.get_all_ip_summaries()
    }


@router.get("/decisions")
def get_decisions(request: Request, limit: int = 100):
    """
    Retrieves the most recent decision logs from MongoDB.
    """
    ltm = request.app.state.long_term_memory
    if ltm is None:
        raise HTTPException(
            status_code=503,
            detail="Long-term memory unavailable — MongoDB not connected"
        )
    
    try:
        records = list(ltm.collection.find().sort("timestamp", -1).limit(limit))
        # Convert ObjectId to string for JSON serialization
        for r in records:
            r["_id"] = str(r["_id"])
            if isinstance(r.get("timestamp"), datetime):
                r["timestamp"] = r["timestamp"].isoformat()
        
        total = ltm.collection.count_documents({})
        
        return {
            "total": total,
            "count": len(records),
            "records": records
        }
    except Exception as e:
        logger.error(f"[Evaluation] MongoDB query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/decisions/purge")
def purge_all_decisions(request: Request):
    """
    Deletes all decision records from the long-term memory (MongoDB).
    Used by the settings dashboard to clear simulation history.
    """
    ltm = request.app.state.long_term_memory
    if ltm is None:
        raise HTTPException(
            status_code=503,
            detail="Long-term memory unavailable — MongoDB not connected"
        )
    
    try:
        result = ltm.collection.delete_many({})
        logger.info(f"[Evaluation] Purged {result.deleted_count} records from database.")
        return {
            "status": "success",
            "message": f"Successfully deleted {result.deleted_count} records.",
            "deleted_count": result.deleted_count
        }
    except Exception as e:
        logger.error(f"[Evaluation] MongoDB purge failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/decisions/purge-by-age")
def purge_decisions_by_age(request: Request, hours: float = Query(..., gt=0, description="Delete records older than this many hours")):
    """
    Deletes decision records older than the specified number of hours.
    Called when the user sets a data retention policy in Settings > Data & Logs.
    E.g. hours=3 removes everything older than 3 hours from MongoDB.
    """
    ltm = request.app.state.long_term_memory
    if ltm is None:
        raise HTTPException(
            status_code=503,
            detail="Long-term memory unavailable — MongoDB not connected"
        )
    
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        result = ltm.collection.delete_many({"timestamp": {"$lt": cutoff}})
        logger.info(f"[Evaluation] Purged {result.deleted_count} records older than {hours}h (cutoff={cutoff.isoformat()}).")
        return {
            "status": "success",
            "hours": hours,
            "cutoff": cutoff.isoformat(),
            "message": f"Deleted {result.deleted_count} records older than {hours} hour(s).",
            "deleted_count": result.deleted_count
        }
    except Exception as e:
        logger.error(f"[Evaluation] MongoDB purge-by-age failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/models/available")
def get_available_models():
    """
    Returns the list of available LLM models configured in the .env file.
    ORDER: 1. Claude, 2. Gemini, 3. Groq
    """
    models = []

    # 1. OpenRouter (Claude 3.7 Sonnet)
    if os.getenv("OPENROUTER_API_KEY"):
        or_model = os.getenv("OPENROUTER_LLM_MODEL", "anthropic/claude-3.7-sonnet")
        models.append({
            "id": "openrouter",
            "provider": "Anthropic — Claude 3.7",
            "model": "Claude 3.7 Sonnet",
            "display_name": "Claude 3.7 Sonnet",
            "description": "The gold standard for autonomous logic and policy execution.",
            "env_key": "OPENROUTER_API_KEY"
        })

    # 2. Google Gemini (Gemini 3 Pro)
    if os.getenv("GEMINI_API_KEY"):
        gemini_model = os.getenv("GEMINI_LLM_MODEL", "models/gemini-3-pro-preview")
        models.append({
            "id": "google",
            "provider": "Google — Gemini 3",
            "model": "Gemini 3 Pro (Preview)",
            "display_name": "Gemini 3 Pro",
            "description": "Advanced multi-modal reasoning and deep PCAP analysis.",
            "env_key": "GEMINI_API_KEY"
        })

    # 3. Groq (Llama 4 Scout)
    if os.getenv("GROQ_API_KEY"):
        groq_model = os.getenv("GROQ_LLM_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
        models.append({
            "id": "groq",
            "provider": "Groq — Ultra Fast",
            "model": "Llama 4 Scout (17B)",
            "display_name": "Llama 4 Scout (17B)",
            "description": "Next-gen inference, optimized for real-time security routing.",
            "env_key": "GROQ_API_KEY"
        })

    # Active provider from runtime config
    try:
        from ..agent.llm_config import get_provider_info
        info = get_provider_info()
        active_provider = info["provider"]
        active_model = info["model"]
    except Exception:
        active_provider = os.getenv("SENTINEL_LLM_PROVIDER", "").lower()
        active_model    = os.getenv("SENTINEL_LLM_MODEL", "")

    return {
        "active_provider": active_provider,
        "active_model":    active_model,
        "models":          models
    }