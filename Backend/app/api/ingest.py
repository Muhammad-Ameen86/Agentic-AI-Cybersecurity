import logging
from fastapi import APIRouter, Request, HTTPException
from ..schemas.requests import PredictRequest
from ..services.prediction_service import predict_flow

logger = logging.getLogger("sentinel.ingest")
router = APIRouter()


@router.post("/")
def ingest(payload: PredictRequest, request: Request):
    """
    Ingestion endpoint — receives raw packet data,
    runs full prediction pipeline, returns decision.

    FIX: Was returning {"received": True} and doing nothing.
    Now wired to the full prediction pipeline — same as /predict
    but designed for high-volume automated ingestion from sensors.

    Use /predict for single interactive predictions.
    Use /ingest for automated pipeline ingestion.
    """
    logger.info(f"[Ingest] Received packet from srcip={payload.data.get('srcip', 'unknown')}")

    try:
        result = predict_flow(payload.data, request)
        return {
            "status": "processed",
            "srcip":      result["srcip"],
            "prediction": result["prediction"],
            "decision":   result["decision"],
            "confidence": result["confidence"],
            "latency_ms": result["latency_ms"],
        }
    except Exception as e:
        logger.error(f"[Ingest] Processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))