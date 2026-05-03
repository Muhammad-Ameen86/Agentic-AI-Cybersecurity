from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any


class ShortTermMemory:
    """
    In-process short-term memory per IP address.
    Tracks behavior patterns across the current session.

    Enhanced:
    - tracks request/action history
    - supports escalation detection
    - recent activity windows
    - average confidence
    - stores last model + last reason for dashboard archive
    """

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "requests": 0,
                "attacks": 0,
                "blocks": 0,
                "allows": 0,
                "alerts": 0,
                "monitors": 0,
                "attack_types": [],
                "action_history": [],
                "confidence_history": [],
                "first_seen": None,
                "last_seen": None,
                "false_positive_count": 0,

                # ✅ NEW FOR DASHBOARD
                "last_model": "unknown",
                "last_reason": "",
            }
        )

    # ── Update ────────────────────────────────────────────────
    def update(
        self,
        srcip: str,
        prediction: int,
        action: str,
        confidence: float = 0.0,
        attack_type: str = "Unknown",
        model: str = "unknown",
        reason: str = "",
    ):
        s = self._store[srcip]
        now = datetime.now(timezone.utc)

        s["requests"] += 1
        s["last_seen"] = now
        s["last_model"] = model
        s["last_reason"] = reason

        if s["first_seen"] is None:
            s["first_seen"] = now

        if prediction == 1:
            s["attacks"] += 1
            if attack_type and attack_type not in s["attack_types"]:
                s["attack_types"].append(attack_type)

        action_upper = action.upper()
        if action_upper == "BLOCK":
            s["blocks"] += 1
        elif action_upper == "ALLOW":
            s["allows"] += 1
        elif action_upper == "ALERT":
            s["alerts"] += 1
        elif action_upper == "MONITOR":
            s["monitors"] += 1

        # Keep last 20 actions
        s["action_history"].append((now.isoformat(), action_upper))
        s["action_history"] = s["action_history"][-20:]

        # Keep last 20 confidence scores
        s["confidence_history"].append(round(confidence, 4))
        s["confidence_history"] = s["confidence_history"][-20:]

    # ── Get stats ─────────────────────────────────────────────
    def get_stats(self, srcip: str) -> Dict[str, Any]:
        return self._store[srcip]

    # ── Recent activity window ────────────────────────────────
    def get_recent_request_count(self, srcip: str, window_minutes: int = 5) -> int:
        s = self._store[srcip]
        if not s["action_history"]:
            return 0

        cutoff = datetime.now(timezone.utc).timestamp() - (window_minutes * 60)
        count = 0

        for ts_str, _ in s["action_history"]:
            try:
                ts = datetime.fromisoformat(ts_str).timestamp()
                if ts >= cutoff:
                    count += 1
            except Exception:
                continue

        return count

    # ── Escalation detection ──────────────────────────────────
    def is_escalating(self, srcip: str) -> bool:
        s = self._store[srcip]
        history = s["action_history"][-5:]

        if len(history) < 3:
            return False

        threat_actions = {"BLOCK", "ALERT"}
        threat_count = sum(1 for _, a in history if a in threat_actions)

        return threat_count >= 3

    # ── Avg confidence ────────────────────────────────────────
    def get_avg_confidence(self, srcip: str) -> float:
        s = self._store[srcip]
        hist = s["confidence_history"]

        if not hist:
            return 0.0

        return round(sum(hist) / len(hist), 4)

    # ── Mark false positive ───────────────────────────────────
    def mark_false_positive(self, srcip: str):
        s = self._store[srcip]
        s["false_positive_count"] += 1
        s["attacks"] = 0
        s["blocks"] = 0
        s["alerts"] = 0
        s["monitors"] = 0
        s["attack_types"] = ["False Positive (Cleared)"]
        s["last_reason"] = "Analyst cleared IP as False Positive"
        s["action_history"] = [(datetime.now(timezone.utc).isoformat(), "ALLOW")]

    # ── Summary ───────────────────────────────────────────────
    def get_summary(self, srcip: str) -> Dict[str, Any]:
        s = self._store[srcip]

        return {
            "requests": s["requests"],
            "attacks": s["attacks"],
            "blocks": s["blocks"],
            "alerts": s["alerts"],
            "attack_types": s["attack_types"],
            "is_escalating": self.is_escalating(srcip),
            "recent_5min": self.get_recent_request_count(srcip, 5),
            "avg_confidence": self.get_avg_confidence(srcip),
            "false_positives": s["false_positive_count"],
            "first_seen": s["first_seen"].isoformat() if s["first_seen"] else None,
            "last_seen": s["last_seen"].isoformat() if s["last_seen"] else None,

            # ✅ NEW
            "last_model": s["last_model"],
            "last_reason": s["last_reason"],
        }

    # ── All IPs ───────────────────────────────────────────────
    def get_all_ip_summaries(self) -> Dict[str, Dict]:
        return {ip: self.get_summary(ip) for ip in list(self._store)}