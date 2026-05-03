from fastapi import APIRouter
from pydantic import BaseModel
import random
import time
from datetime import datetime, timezone

router = APIRouter()

# In-memory storage for simulated threats for the dashboard
mock_threats = [
    {
        "id": "#SN-9821",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "srcip": "192.168.1.44",
        "prediction": "Attack",
        "decision": "BLOCK",
        "severity": "Critical",
        "confidence": 0.984,
        "reason": "Escalating attack pattern detected",
        "model": "random_forest"
    }
]

class AgentDeployRequest(BaseModel):
    agent_type: str
    zone: str
    model: str

@router.get("/metrics")
def get_dashboard_metrics():
    """Provides high-level metrics for the dashboard header stats."""
    return {
        "total_traffic_pb": round(random.uniform(4.0, 4.5), 2),
        "active_threats": len([t for t in mock_threats if t['severity'] == "Critical"]),
        "agent_health_pct": 99.9,
        "global_latency_ms": random.randint(12, 18)
    }

@router.get("/network/throughput")
def get_network_throughput():
    """Returns simulated inbound/outbound network throughput data."""
    now = int(time.time())
    data = []
    for i in range(20):
        data.append({
            "time": now - (20 - i) * 60,
            "inbound": random.randint(300, 800),
            "outbound": random.randint(100, 400)
        })
    return data

@router.get("/threats/recent")
def get_recent_threats():
    """Returns the most recent processed threats for the anomalies table."""
    return sorted(mock_threats, key=lambda x: x["timestamp"], reverse=True)[:50]

@router.get("/agents/status")
def get_agents_status():
    """Returns the status of active AI analysis agents."""
    return {
        "active_agents": 14,
        "status": "NOMINAL",
        "uptime": "99.9%"
    }

@router.post("/agents/deploy")
def deploy_agent(req: AgentDeployRequest):
    """Simulates deploying a new AI agent to a network zone."""
    return {
        "status": "success",
        "message": f"Agent {req.agent_type} successfully deployed to {req.zone} using {req.model}.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
