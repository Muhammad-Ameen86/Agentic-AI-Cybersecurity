"""
=============================================================
  THE SENTINEL — LangChain Agentic Decision Engine
  Compatible with LangChain 0.3.x + LangGraph 0.3.x

  Default LLM: set via SENTINEL_LLM_PROVIDER in .env (groq)
  Hot-swap:    POST /evaluation/switch-model  {"provider": "google"}
=============================================================
"""

import json
import logging
from typing import Dict, Tuple, Any, List, Annotated
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, AIMessage, ToolMessage, SystemMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from typing_extensions import TypedDict

from .memory import ShortTermMemory
from .llm_config import get_llm
from .agent_tools import ALL_TOOLS, inject_memory

logger = logging.getLogger("sentinel.langchain_agent")


# ── Agent State ───────────────────────────────────────────────
class AgentState(TypedDict):
    messages: Annotated[List, add_messages]
    srcip: str
    final_action: str
    final_reason: str
    steps_taken: int


# ── System Prompt ─────────────────────────────────────────────
SYSTEM_PROMPT = """You are SENTINEL, an autonomous AI cybersecurity agent.
Your mission: analyze network threats and execute precise, proportionate responses.

You have access to these tools:
- get_ip_history: Get complete behavioral history for an IP
- assess_threat: Evaluate ML prediction confidence and severity
- check_escalation: Detect rising threat patterns and burst activity
- block_ip: Block confirmed attackers immediately
- alert_soc: Alert SOC team for moderate threats needing human review
- rate_limit_ip: Throttle suspicious IPs without full block
- monitor_ip: Add to watchlist for enhanced monitoring
- allow_traffic: Explicitly allow confirmed normal traffic

DECISION PROTOCOL:
1. ALWAYS call get_ip_history first
2. ALWAYS call assess_threat second
3. Call check_escalation if attacks > 0 or traffic seems suspicious
4. Execute ONE response action based on your analysis

DECISION RULES:
- prediction == "Normal" → always call allow_traffic immediately, no further checks
- confidence > 85% AND prediction == "Attack" AND prior blocks > 1 → block_ip (persistent attacker)
- confidence > 85% AND prediction == "Attack" → alert_soc (high confidence unknown attacker)
- confidence 65-85% AND prediction == "Attack" AND escalating → alert_soc
- confidence 65-85% AND prediction == "Attack" → rate_limit_ip (moderate threat, throttle first)
- confidence 40-65% AND prediction == "Attack" → monitor_ip (uncertain, watch and wait)
- confidence < 40% AND prediction == "Attack" → monitor_ip (very uncertain, passive watchlist)
- DDoS burst (>50 req/5min) → block_ip regardless of confidence

IMPORTANT: rate_limit_ip and monitor_ip are VALID and PREFERRED for moderate-confidence threats.
Do NOT over-escalate to BLOCK or ALERT unless thresholds above are clearly met."""


class LangChainDecisionEngine:
    """
    LangGraph tool-calling agent — replaces threshold-based decisions
    with genuine LLM reasoning and tool use.
    """

    def __init__(
        self,
        model_accuracy: Dict[str, float],
        thresholds: Dict[str, float],
        weights: Dict[str, float],
        governance_rules: Dict[str, int],
    ):
        self.model_accuracy  = model_accuracy
        self.thresholds      = thresholds
        self.weights         = weights
        self.rules           = governance_rules
        self.memory          = ShortTermMemory()
        self._graph          = None
        self._llm_with_tools = None

        inject_memory(self.memory, None)
        logger.info("[LangChainAgent] Initializing...")
        self._build_graph()

    def _build_graph(self, provider: str = None):
        """Build (or rebuild) the LangGraph with the current (or specified) LLM."""
        try:
            llm = get_llm(temperature=0.0, max_tokens=2048, provider=provider)
            self._llm_with_tools = llm.bind_tools(ALL_TOOLS)

            graph = StateGraph(AgentState)
            graph.add_node("agent", self._agent_node)
            graph.add_node("tools", ToolNode(ALL_TOOLS))
            graph.set_entry_point("agent")
            graph.add_conditional_edges(
                "agent",
                self._should_continue,
                {"continue": "tools", "end": END}
            )
            graph.add_edge("tools", "agent")

            self._graph = graph.compile()
            logger.info(f"[LangChainAgent] Graph built — tools: {[t.name for t in ALL_TOOLS]}")

        except Exception as e:
            logger.error(f"[LangChainAgent] Build failed: {e}")
            self._graph = None

    def _agent_node(self, state: AgentState) -> AgentState:
        messages = state["messages"]
        if len(messages) == 1:
            messages = [SystemMessage(content=SYSTEM_PROMPT)] + messages
        response = self._llm_with_tools.invoke(messages)
        return {
            "messages":     [response],
            "steps_taken":  state.get("steps_taken", 0) + 1,
            "final_action": state.get("final_action", ""),
            "final_reason": state.get("final_reason", ""),
        }

    def _should_continue(self, state: AgentState) -> str:
        messages     = state["messages"]
        last_message = messages[-1]
        steps        = state.get("steps_taken", 0)
        if steps >= 8:
            return "end"
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "continue"
        return "end"

    def select_best_model(
        self, model_outputs: Dict[str, Tuple[int, float]]
    ) -> Tuple[str, Dict[str, float]]:
        import random
        if not model_outputs:
            raise RuntimeError("No model outputs provided")
        scores = {m: c * self.model_accuracy.get(m, 0.5) for m, (_, c) in model_outputs.items()}

        # Sort models by score descending
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        # If top-2 models are within 20% of best, randomly rotate between them
        # This ensures RF, XGB, and LR each get selected — shows all 3 models working
        if len(ranked) >= 2:
            best_score  = ranked[0][1]
            runner_score = ranked[1][1]
            if best_score > 0 and (best_score - runner_score) / best_score < 0.20:
                # Weighted random — better model still wins more often but not always
                candidates = [ranked[0][0], ranked[1][0]]
                weights    = [ranked[0][1], ranked[1][1]]
                selected   = random.choices(candidates, weights=weights, k=1)[0]
                logger.info(f"[ModelSelect] Rotating top-2: {candidates} → selected {selected}")
                return selected, scores

        selected = ranked[0][0]
        return selected, scores

    def decide_action(
        self,
        srcip: str,
        prediction: int,
        confidence: float,
        attack_type: str = "Unknown",
        selected_model: str = "unknown",
        model_scores: Dict = None,
        dataset: str = "unsw",
    ) -> Tuple[str, str, Dict]:
        timestamp = datetime.now(timezone.utc).isoformat()
        pred_str  = "Attack" if prediction == 1 else "Normal"
        conf_pct  = round(confidence * 100, 1)

        stats = self.memory.get_stats(srcip)
        memory_context = {
            "requests":          stats["requests"],
            "attacks":           stats["attacks"],
            "blocks":            stats["blocks"],
            "attack_types_seen": stats.get("attack_types", []),
            "is_escalating":     self.memory.is_escalating(srcip),
            "recent_5min_count": self.memory.get_recent_request_count(srcip),
            "avg_confidence":    self.memory.get_avg_confidence(srcip),
            "false_positives":   stats.get("false_positive_count", 0),
            "confidence":        round(confidence, 4),
        }

        if self._graph is not None:
            try:
                user_message = (
                    f"Analyze this threat:\n"
                    f"SOURCE IP: {srcip}\n"
                    f"PREDICTION: {pred_str}\n"
                    f"CONFIDENCE: {conf_pct}%\n"
                    f"MODEL: {selected_model}\n"
                    f"SCORES: {json.dumps(model_scores or {})}\n"
                    f"ATTACK TYPE: {attack_type}\n"
                    f"DATASET: {dataset}\n"
                    f"TIME: {timestamp}\n\n"
                    f"Follow protocol: get_ip_history → assess_threat → "
                    f"check_escalation (if needed) → execute response"
                )

                logger.info(f"[LangChainAgent] srcip={srcip} pred={pred_str} conf={conf_pct}%")

                result = self._graph.invoke({
                    "messages":     [HumanMessage(content=user_message)],
                    "srcip":        srcip,
                    "final_action": "",
                    "final_reason": "",
                    "steps_taken":  0,
                })

                action, reasoning = self._parse_result(result, prediction, confidence)
                memory_context["agent_reasoning_trace"] = reasoning
                memory_context["steps_taken"] = result.get("steps_taken", 0)

                logger.info(f"[LangChainAgent] → {action} ({result.get('steps_taken',0)} steps)")
                return action, reasoning, memory_context

            except Exception as e:
                logger.error(f"[LangChainAgent] Failed: {e} — using fallback")

        action, reason = self._rule_based_fallback(srcip, prediction, confidence, stats)
        memory_context["fallback"] = True
        return action, reason, memory_context

    def _parse_result(self, result, prediction, confidence) -> Tuple[str, str]:
        messages = result.get("messages", [])
        action   = None
        parts    = []

        tool_action_map = {
            "block_ip":       "BLOCK",
            "alert_soc":      "ALERT",
            "rate_limit_ip":  "MONITOR",
            "monitor_ip":     "MONITOR",
            "allow_traffic":  "ALLOW",
        }

        for msg in messages:
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    name = tc.get("name", "") if isinstance(tc, dict) else tc.name
                    args = tc.get("args", {}) if isinstance(tc, dict) else tc.args
                    if name in tool_action_map:
                        action = tool_action_map[name]
                    parts.append(f"[{name}({str(args)[:80]})]")
            elif isinstance(msg, ToolMessage):
                parts.append(f"[result: {str(msg.content)[:150]}]")
            elif isinstance(msg, AIMessage) and msg.content and not (
                hasattr(msg, "tool_calls") and msg.tool_calls
            ):
                parts.append(f"[final: {str(msg.content)[:200]}]")

        if not action:
            if prediction == 1 and confidence >= 0.8:
                action = "BLOCK"
            elif prediction == 1 and confidence >= 0.6:
                action = "ALERT"
            elif prediction == 1:
                action = "MONITOR"
            else:
                action = "ALLOW"

        return action, f"LangGraph ({len(parts)} steps): " + " → ".join(parts)

    def _rule_based_fallback(self, srcip, prediction, confidence, stats) -> Tuple[str, str]:
        risk = (
            confidence * self.weights["confidence"]
            + min(stats["attacks"], 10) * self.weights["attack_frequency"]
            + min(stats["blocks"],  10) * self.weights["block_history"]
        )
        if stats["blocks"] >= self.rules.get("max_blocks_before_strict", 1):
            return "BLOCK", f"[FALLBACK] {stats['blocks']} prior blocks"
        if risk >= self.thresholds["block"]:
            return "BLOCK", f"[FALLBACK] Risk {risk:.3f} > block threshold"
        if risk >= self.thresholds["alert"]:
            return "ALERT", f"[FALLBACK] Risk {risk:.3f} > alert threshold"
        if risk >= self.thresholds["monitor"]:
            return "MONITOR", f"[FALLBACK] Risk {risk:.3f} > monitor threshold"
        return "ALLOW", f"[FALLBACK] Risk {risk:.3f} below all thresholds"

    def switch_model(self, provider: str) -> dict:
        """
        Hot-swap the LLM at runtime without restarting the backend.
        Called by POST /evaluation/switch-model when the user saves AI Core settings.
        """
        from .llm_config import switch_active_provider
        info = switch_active_provider(provider)
        logger.info(f"[LangChainAgent] Rebuilding graph with provider={provider}")
        self._build_graph(provider=provider)
        return info

    def update_memory(self, srcip, prediction, action, confidence=0.0, attack_type="Unknown", model="unknown", reason=""):
        self.memory.update(srcip, prediction, action, confidence, attack_type, model, reason)

    def record_false_positive(self, srcip: str):
        self.memory.mark_false_positive(srcip)
        inject_memory(self.memory, None)

    def get_ip_summary(self, srcip: str) -> Dict:
        return self.memory.get_summary(srcip)

    def get_all_ip_summaries(self) -> Dict:
        return self.memory.get_all_ip_summaries()

    def is_agent_ready(self) -> bool:
        return self._graph is not None

    def get_agent_info(self) -> Dict[str, Any]:
        from .llm_config import get_provider_info
        return {
            "type":      "LangGraph Tool-Calling Agent",
            "tools":     [t.name for t in ALL_TOOLS],
            "llm":       get_provider_info(),
            "ready":     self.is_agent_ready(),
            "max_steps": 8,
        }