from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class PredictRequest(BaseModel):
    """
    Incoming prediction request schema.
    'data' contains raw packet features as key-value pairs.
    'dataset' selects which trained model set to use.
    """
    data: Dict[str, Any] = Field(
        ...,
        description="Raw packet/flow features as key-value pairs",
        example={
            "srcip":   "192.168.1.44",
            "dstip":   "10.0.0.1",
            "proto":   "tcp",
            "sbytes":  1500,
            "dbytes":  800,
            "dur":     0.05,
            "label":   0
        }
    )
    dataset: Optional[str] = Field(
        default="unsw",
        description="Which dataset's model to use: 'unsw' or 'cic'"
    )


class PredictResponse(BaseModel):
    srcip:          str
    dataset:        str
    selected_model: str
    prediction:     str
    confidence:     float
    decision:       str
    reason:         str
    latency_ms:     float
    agent_reasoning: Dict[str, Any]


class FeedbackRequest(BaseModel):
    srcip:    str
    feedback: str = Field(..., description="'false_positive' or 'confirmed_attack'")
    operator: Optional[str] = Field(default="anonymous")