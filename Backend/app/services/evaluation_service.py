"""
THE SENTINEL — Evaluation Router v3.1
Fixed /summary to include unique_ips.
Added /memory/active used by log_archives and network_nodes pages.
"""
from fastapi import APIRouter, Request
from collections import Counter

router = APIRouter()


@router.get("/summary")
def evaluation_summary(request: Request):
    ltm = request.app.state.long_term_memory
    try:
        records = list(ltm.collection.find({}, {"_id": 0}))
    except Exception:
        return {"message": "MongoDB not available"}

    if not records:
        return {"message": "No evaluation data yet"}

    decisions   = Counter(r["decision"]   for r in records)
    models      = Counter(r["model"]      for r in records)
    predictions = Counter(r["prediction"] for r in records)
    unique_ips  = len(set(r["srcip"] for r in records))

    attack_blocks = sum(
        1 for r in records
        if r["prediction"] == "Attack" and r["decision"] == "BLOCK"
    )

    return {
        "total_requests":          len(records),
        "unique_ips":              unique_ips,
        "decision_distribution":   dict(decisions),
        "model_usage":             dict(models),
        "prediction_distribution": dict(predictions),
        "attack_block_rate":       round(
            attack_blocks / max(1, predictions.get("Attack", 1)), 3
        ),
    }


@router.get("/memory/active")
def active_memory(request: Request):
    ltm = request.app.state.long_term_memory
    try:
        records = list(ltm.collection.find({}, {"_id": 0}))
    except Exception:
        return {"ip_summaries": {}, "active_ips": 0}

    ip_map = {}
    for r in records:
        ip = r.get("srcip", "unknown")
        if ip not in ip_map:
            ip_map[ip] = {
                "requests": 0, "attacks": 0, "blocks": 0,
                "alerts": 0, "monitors": 0, "allows": 0,
                "confidence_sum": 0.0, "attack_types": set(),
                "models_used": set(), "is_escalating": False,
                "false_positives": 0, "first_seen": None,
                "last_seen": None, "last_reason": "", "last_model": "",
            }
        s = ip_map[ip]
        s["requests"] += 1

        dec = r.get("decision", "")
        if dec == "BLOCK":
            s["blocks"]   += 1
        elif dec == "ALERT":
            s["alerts"]   += 1
        elif dec == "MONITOR":
            s["monitors"] += 1
        elif dec == "ALLOW":
            s["allows"]   += 1

        if r.get("prediction") == "Attack":
            s["attacks"] += 1

        s["confidence_sum"] += r.get("confidence", 0)

        ts = r.get("timestamp")
        if ts:
            if not s["first_seen"] or ts < s["first_seen"]:
                s["first_seen"] = ts
            if not s["last_seen"] or ts > s["last_seen"]:
                s["last_seen"] = ts

        cat = r.get("raw_data", {}).get("attack_cat", "Unknown")
        if cat and cat != "Unknown":
            s["attack_types"].add(cat)

        m = r.get("model", "")
        if m:
            s["models_used"].add(m)
            s["last_model"] = m

        s["last_reason"]   = r.get("reason", "")
        s["is_escalating"] = s["attacks"] >= 2

    def ts_fmt(t):
        if not t:
            return None
        return t.isoformat() if hasattr(t, "isoformat") else str(t)

    result = {}
    for ip, s in ip_map.items():
        total = max(s["requests"], 1)
        result[ip] = {
            "requests":        s["requests"],
            "attacks":         s["attacks"],
            "blocks":          s["blocks"],
            "alerts":          s["alerts"],
            "monitors":        s["monitors"],
            "allows":          s["allows"],
            "avg_confidence":  round(s["confidence_sum"] / total, 4),
            "attack_types":    list(s["attack_types"]) or ["Unknown"],
            "models_used":     list(s["models_used"]),
            "last_model":      s["last_model"],
            "is_escalating":   s["is_escalating"],
            "false_positives": s["false_positives"],
            "first_seen":      ts_fmt(s["first_seen"]),
            "last_seen":       ts_fmt(s["last_seen"]),
            "last_reason":     s["last_reason"],
        }

    return {"ip_summaries": result, "active_ips": len(result)}


@router.get("/ip/{srcip}")
def ip_history(srcip: str, request: Request):
    ltm = request.app.state.long_term_memory
    try:
        records = list(
            ltm.collection.find({"srcip": srcip}, {"_id": 0})
            .sort("timestamp", -1).limit(50)
        )
    except Exception:
        return {"records": [], "total_records": 0}

    for r in records:
        if "timestamp" in r and hasattr(r["timestamp"], "isoformat"):
            r["timestamp"] = r["timestamp"].isoformat()

    return {"srcip": srcip, "records": records, "total_records": len(records)}


@router.post("/feedback/false-positive/{srcip}")
def false_positive(srcip: str, request: Request):
    agent = request.app.state.agent
    if hasattr(agent, "record_false_positive"):
        agent.record_false_positive(srcip)
    elif hasattr(agent, "memory") and hasattr(agent.memory, "ip_stats"):
        s = agent.memory.ip_stats[srcip]
        s["false_positive_count"] = s.get("false_positive_count", 0) + 1
    return {"message": f"False positive recorded for {srcip}"}