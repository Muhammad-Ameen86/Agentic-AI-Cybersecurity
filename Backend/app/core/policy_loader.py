import json
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("sentinel.policy_loader")


class PolicyLoader:
    """
    Loads and provides access to agent governance policies.

    FIX: Added fallback defaults if any key is missing from JSON.
    Added get_all() for full policy inspection.
    Now handles policy_v2 fields (burst_threshold) gracefully.
    """

    # Safe defaults — system works even if policy file is incomplete
    _DEFAULTS = {
        "thresholds": {
            "allow":   0.0,
            "monitor": 0.4,
            "alert":   0.6,
            "block":   0.8,
        },
        "risk_weights": {
            "confidence":       0.6,
            "attack_frequency": 0.25,
            "block_history":    0.15,
        },
        "governance_rules": {
            "repeat_attack_limit":      2,
            "max_blocks_before_strict": 1,
            "burst_threshold":          100,
        },
    }

    def __init__(self, policy_path: Path):
        if not policy_path.exists():
            raise FileNotFoundError(
                f"Policy file not found: {policy_path}\n"
                f"Expected: Backend/app/policies/policy_v1.json"
            )

        with open(policy_path, "r") as f:
            self.policy: Dict[str, Any] = json.load(f)

        logger.info(
            f"[PolicyLoader] Loaded policy v{self.get_version()} "
            f"from {policy_path}"
        )

    def get_thresholds(self) -> Dict[str, float]:
        return self.policy.get(
            "thresholds", self._DEFAULTS["thresholds"]
        )

    def get_weights(self) -> Dict[str, float]:
        return self.policy.get(
            "risk_weights", self._DEFAULTS["risk_weights"]
        )

    def get_governance_rules(self) -> Dict[str, Any]:
        rules = self._DEFAULTS["governance_rules"].copy()
        rules.update(
            self.policy.get("governance_rules", {})
        )
        return rules

    def get_version(self) -> str:
        return self.policy.get("policy_version", "unknown")

    def get_all(self) -> Dict[str, Any]:
        """Returns the full policy dict — for health/debug endpoints."""
        return self.policy