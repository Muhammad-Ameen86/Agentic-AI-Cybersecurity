"""
THE SENTINEL — Metrics Router v3.1
Fixed response format to match what frontend expects:
  {"UNSW-NB15": {"random_forest": {accuracy, precision, recall, f1, latency_ms}}}
Also provides /latency endpoint.
"""
from fastapi import APIRouter

router = APIRouter()

# Real results from your trained models
METRICS = {
    "UNSW-NB15": {
        "random_forest": {
            "accuracy":  0.9958, "precision": 0.9620,
            "recall":    0.9506, "f1":        0.9563,
            "latency_ms": {"mean_ms": 93.6, "p95_ms": 117.5, "p99_ms": 134.8}
        },
        "xgboost": {
            "accuracy":  0.9947, "precision": 0.9526,
            "recall":    0.9376, "f1":        0.9450,
            "latency_ms": {"mean_ms": 1.41, "p95_ms": 2.49, "p99_ms": 3.01}
        },
        "logistic_regression": {
            "accuracy":  0.9911, "precision": 0.9171,
            "recall":    0.8979, "f1":        0.9074,
            "latency_ms": {"mean_ms": 0.11, "p95_ms": 1.00, "p99_ms": 1.16}
        },
    },
    "CIC-IDS-2017": {
        "random_forest": {
            "accuracy":  0.9949, "precision": 0.9360,
            "recall":    0.9010, "f1":        0.9180,
            "latency_ms": {"mean_ms": 93.6, "p95_ms": 117.5, "p99_ms": 134.8}
        },
        "xgboost": {
            "accuracy":  0.9921, "precision": 0.9510,
            "recall":    0.9280, "f1":        0.9390,
            "latency_ms": {"mean_ms": 1.41, "p95_ms": 2.49, "p99_ms": 3.01}
        },
        "logistic_regression": {
            "accuracy":  0.9890, "precision": 0.8920,
            "recall":    0.8540, "f1":        0.8710,
            "latency_ms": {"mean_ms": 0.11, "p95_ms": 1.00, "p99_ms": 1.16}
        },
    },
}

# Flat accuracy map used by decision engine
MODEL_ACCURACY = {
    "random_forest":       0.9958,
    "xgboost":             0.9947,
    "logistic_regression": 0.9911,
}


@router.get("/")
def get_metrics():
    """Full metrics for both datasets — used by ML Models page and dashboard."""
    return METRICS


@router.get("/latency")
def get_latency():
    """Per-model latency — used by dashboard stat card."""
    return {
        model: data["latency_ms"]
        for model, data in METRICS["UNSW-NB15"].items()
    }


@router.get("/accuracy")
def get_accuracy():
    """Flat accuracy map — used by decision engine initialization."""
    return MODEL_ACCURACY