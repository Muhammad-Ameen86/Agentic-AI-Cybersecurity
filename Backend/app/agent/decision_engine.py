"""
THE SENTINEL — Agent Decision Engine v3.1
FIXED: Normalized risk score so all 4 decisions appear.

Old bug: risk = conf*0.6 + attacks*0.25 + blocks*0.15
  With attacks=3: risk = 0.36 + 0.75 + 0.15 = 1.26 → always BLOCK

Fix: normalize counts to 0-1 before weighting:
  risk = conf*0.6 + (attacks/10)*0.25 + (blocks/5)*0.15
  With attacks=3: risk = 0.36 + 0.075 + 0.03 = 0.465 → ALERT (correct)

Decision map:
  risk < 0.40  → ALLOW   (low confidence, fresh IP)
  risk < 0.60  → MONITOR (suspicious but uncertain)
  risk < 0.80  → ALERT   (moderate threat)
  risk >= 0.80 → BLOCK   (confirmed high risk)
"""
import logging
from typing import Dict, Tuple
from .memory import ShortTermMemory

logger = logging.getLogger("sentinel.decision_engine")


class AgentDecisionEngine:
    def __init__(self, model_accuracy, thresholds, weights, governance_rules):
        self.model_accuracy = model_accuracy
        self.thresholds     = thresholds
        self.weights        = weights
        self.rules          = governance_rules
        self.memory         = ShortTermMemory()

    def select_best_model(self, model_outputs: Dict[str, Tuple[int, float]]):
        if not model_outputs:
            raise RuntimeError("No model outputs")
        scores = {m: round(conf * self.model_accuracy.get(m, 0.5), 6)
                  for m, (_, conf) in model_outputs.items()}
        return max(scores, key=scores.get), scores

    def decide_action(self, srcip: str, prediction: int, confidence: float):
        stats = self.memory.get_stats(srcip)

        # Normalize counts to 0.0–1.0
        attacks_norm = min(stats["attacks"], 10) / 10.0
        blocks_norm  = min(stats["blocks"],   5) /  5.0

        risk = round(min(
            confidence    * self.weights["confidence"]
            + attacks_norm * self.weights["attack_frequency"]
            + blocks_norm  * self.weights["block_history"],
            1.0
        ), 4)

        memory_context = {
            "requests":      stats["requests"],
            "attacks":       stats["attacks"],
            "blocks":        stats["blocks"],
            "risk_score":    risk,
            "confidence":    round(confidence, 4),
            "is_escalating": stats["attacks"] >= 2,
        }

        max_blocks   = self.rules.get("max_blocks_before_strict", 3)
        repeat_limit = self.rules.get("repeat_attack_limit", 4)

        # Governance overrides
        if stats["blocks"] >= max_blocks:
            return "BLOCK", f"Strict mode: {stats['blocks']} prior blocks | risk {risk}", memory_context
        if prediction == 1 and stats["attacks"] >= repeat_limit:
            return "BLOCK", f"Repeat attacker: {stats['attacks']} attacks | escalating to BLOCK", memory_context

        # Active Threat Overrides
        if prediction == 1:
            if confidence >= 0.85:
                return "BLOCK", f"Critical confidence attack ({confidence*100:.1f}%) | Immediate Isolation", memory_context
            if risk < t["monitor"]:
                return "MONITOR", f"Suspicious Activity ({confidence*100:.1f}%) | Forced watch despite low threshold", memory_context

        # Threshold decisions
        t = self.thresholds
        if risk >= t["block"]:
            return "BLOCK",   f"Risk {risk:.3f} ≥ block threshold {t['block']} | conf {confidence*100:.1f}%", memory_context
        if risk >= t["alert"]:
            return "ALERT",   f"Risk {risk:.3f} ≥ alert threshold {t['alert']} | Moderate risk — alerting SOC", memory_context
        if risk >= t["monitor"]:
            return "MONITOR", f"Risk {risk:.3f} ≥ monitor threshold {t['monitor']} | Low-confidence suspicious activity", memory_context
        return "ALLOW",       f"Risk {risk:.3f} below all thresholds | conf {confidence*100:.1f}% — normal traffic", memory_context

    def update_memory(self, srcip: str, prediction: int, action: str, confidence: float = 0.0, attack_type: str = "Unknown", model: str = "unknown", reason: str = ""):
        self.memory.update(srcip, prediction, action, confidence, attack_type, model, reason)

    def get_ip_summary(self, srcip: str) -> Dict:
        s = self.memory.get_stats(srcip)
        return {
            "requests":       s["requests"],
            "attacks":        s["attacks"],
            "blocks":         s["blocks"],
            "alerts":         s.get("alerts", 0),
            "is_escalating":  s["attacks"] >= 2,
            "avg_confidence": s.get("avg_confidence", 0),
            "recent_5min":    s.get("recent_5min", 0),
        }

    def get_all_ip_summaries(self) -> Dict:
        return self.memory.get_all_ip_summaries()