import logging
from fastapi import APIRouter, Request, HTTPException
from ..schemas.requests import PredictRequest
from ..services.prediction_service import predict_flow
from ..api.websocket import broadcast_threat_event

logger = logging.getLogger("sentinel.predict")
router = APIRouter()


@router.post("/")
async def predict(payload: PredictRequest, request: Request):
    try:
        result = predict_flow(payload.data, request)

        await broadcast_threat_event(
            srcip      = result["srcip"],
            prediction = result["prediction"],
            decision   = result["decision"],
            confidence = result["confidence"],
            reason     = result["reason"],
            model      = result["selected_model"],
        )

        return result

    except RuntimeError as e:
        logger.error(f"[Predict] Runtime error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"[Predict] Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")


@router.get("/ip/{srcip}")
async def get_ip_status(srcip: str, request: Request):
    agent = request.app.state.agent
    if not hasattr(agent, "get_ip_summary"):
        raise HTTPException(status_code=501, detail="Not supported")
    summary = agent.get_ip_summary(srcip)
    return {"srcip": srcip, "summary": summary}