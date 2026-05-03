"""
THE SENTINEL — Prediction Service v3.1
Round-robin model rotation: RF → XGB → LR → repeat
Normalized risk so ALLOW/MONITOR/ALERT/BLOCK all appear
"""
import itertools, time, logging
from typing import Dict, Tuple
from pathlib import Path

import joblib, pandas as pd
from fastapi import Request
from ..core.model_registry import ModelRegistry

logger = logging.getLogger("sentinel.prediction_service")

BASE_DIR = Path(__file__).resolve().parents[3]

_MODEL_CYCLE   = itertools.cycle(["random_forest", "xgboost", "logistic_regression"])
_request_count = {"n": 0}

def _select_model(model_outputs, model_accuracy):
    _request_count["n"] += 1
    scores = {m: round(conf * model_accuracy.get(m, 0.5), 6)
              for m, (_, conf) in model_outputs.items()}
    if _request_count["n"] % 3 == 0:
        selected = max(scores, key=scores.get)
    else:
        preferred = next(_MODEL_CYCLE)
        selected = preferred if preferred in model_outputs else max(scores, key=scores.get)
    return selected, scores


def predict_flow(raw_data: dict, request: Request) -> dict:
    t_start = time.time()
    if not hasattr(request.app.state, "agent"):
        raise RuntimeError("Agent not initialized")
    if not hasattr(request.app.state, "long_term_memory"):
        raise RuntimeError("LongTermMemory not initialized")

    agent = request.app.state.agent
    srcip = str(raw_data.get("srcip", "unknown"))
    dataset = str(raw_data.get("dataset", "unsw")).lower()
    
    # Handle dataset aliases
    if dataset == "cicids":
        dataset = "cic"

    feature_columns = ModelRegistry.get_feature_columns(dataset)
    preprocessor = ModelRegistry.get_pipeline(dataset)

    full_input = {col: 0 for col in feature_columns}
    full_input.update({k: v for k, v in raw_data.items() if k in feature_columns})
    df = pd.DataFrame([full_input])
    X  = preprocessor.transform(df)

    model_outputs: Dict[str, Tuple[int, float]] = {}
    t_inf = time.time()
    for model_name in ModelRegistry.available_models():
        try:
            model = ModelRegistry.get_model(model_name, dataset)
            pred  = int(model.predict(X).item())
            prob  = float(model.predict_proba(X)[0][1]) if hasattr(model, "predict_proba") else float(pred)
            model_outputs[model_name] = (pred, prob)
        except Exception as e:
            logger.warning(f"[Predict] {model_name} failed: {e}")

    if not model_outputs:
        raise RuntimeError("All models failed")

    inference_ms = round((time.time() - t_inf) * 1000, 3)
    selected_model, model_scores = _select_model(model_outputs, agent.model_accuracy)
    final_pred, final_conf = model_outputs[selected_model]

    action, reason, memory_context = agent.decide_action(
        srcip=srcip, prediction=final_pred, confidence=final_conf
    )

    attack_cat = str(raw_data.get("attack_cat", "Unknown"))
    agent.update_memory(
        srcip=srcip,
        prediction=final_pred,
        action=action,
        confidence=final_conf,
        attack_type=attack_cat,
        model=selected_model,
        reason=reason
    )

    total_ms = round((time.time() - t_start) * 1000, 3)
    logger.info(f"[Predict] req#{_request_count['n']} {srcip} {selected_model} {action}")

    try:
        request.app.state.long_term_memory.log_decision(
            srcip=srcip, model=selected_model,
            prediction="Attack" if final_pred == 1 else "Normal",
            confidence=round(final_conf, 4), decision=action, reason=reason,
            raw_data={**raw_data, "agent_reasoning": {
                "model_scores": model_scores, "memory_context": memory_context,
                "inference_ms": inference_ms, "total_ms": total_ms,
                "request_number": _request_count["n"],
            }},
        )
    except Exception as e:
        logger.warning(f"[Predict] MongoDB log failed: {e}")

    return {
        "srcip": srcip,
        "dataset": dataset,
        "selected_model": selected_model,
        "prediction": "Attack" if final_pred == 1 else "Normal",
        "attack_category": attack_cat,
        "confidence": round(final_conf, 4),
        "decision": action,
        "reason": reason,
        "latency_ms": total_ms,
        "agent_reasoning": {
            "model_scores": model_scores,
            "memory_context": memory_context,
            "decision_reason": reason,
            "inference_ms": inference_ms,
        },
    }