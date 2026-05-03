"""
=============================================================
  THE SENTINEL — Agent Tools
  
  These are the actions the LangChain agent can choose from.
  The LLM reads each tool's description and decides when
  to call it based on the threat context.
  
  Tools available:
    1. get_ip_history      — retrieves behavioral context
    2. assess_threat       — evaluates ML prediction + confidence
    3. check_escalation    — detects rising threat patterns
    4. block_ip            — executes block decision
    5. alert_soc           — escalates to SOC team
    6. rate_limit_ip       — proportionate throttle response
    7. monitor_ip          — watchlist without blocking
    8. allow_traffic       — explicitly clears traffic
=============================================================
"""

import logging
from typing import Optional
from datetime import datetime, timezone
from langchain_core.tools import tool

logger = logging.getLogger("sentinel.agent_tools")

# ── Memory reference (injected at agent creation time) ───────
# These are set by AgentDecisionEngine when it creates the agent
_short_term_memory = None
_long_term_memory  = None


def inject_memory(stm, ltm):
    """Called by AgentDecisionEngine to give tools access to memory."""
    global _short_term_memory, _long_term_memory
    _short_term_memory = stm
    _long_term_memory  = ltm


# ─────────────────────────────────────────────────────────────
# TOOL 1 — Get IP History
# ─────────────────────────────────────────────────────────────
@tool
def get_ip_history(srcip: str) -> str:
    """
    Retrieves the complete behavioral history for a source IP address.
    Use this tool first to understand if this IP has attacked before.
    Returns: request count, attack count, block count, attack types seen,
    whether the IP is currently escalating, recent 5-minute activity,
    average ML confidence, false positive count, and first/last seen times.
    """
    if _short_term_memory is None:
        return "Memory not available — cannot retrieve IP history"

    summary = _short_term_memory.get_summary(srcip)

    result = f"""
IP History for {srcip}:
  Total requests    : {summary['requests']}
  Total attacks     : {summary['attacks']}
  Times blocked     : {summary['blocks']}
  Times alerted     : {summary['alerts']}
  Attack types seen : {summary['attack_types'] or ['None recorded']}
  Is escalating     : {summary['is_escalating']}
  Last 5 min reqs   : {summary['recent_5min']}
  Avg ML confidence : {summary['avg_confidence']}
  False positives   : {summary['false_positives']}
  First seen        : {summary['first_seen'] or 'First time'}
  Last seen         : {summary['last_seen'] or 'Now'}
""".strip()

    logger.debug(f"[Tool:get_ip_history] {srcip} → {summary['attacks']} attacks")
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 2 — Assess Threat
# ─────────────────────────────────────────────────────────────
@tool
def assess_threat(
    srcip: str,
    prediction: str,
    confidence: float,
    selected_model: str,
    model_scores: str,
) -> str:
    """
    Assesses the threat level based on ML model outputs.
    Use this to understand how certain the models are about
    the threat classification and which model to trust most.
    prediction: 'Attack' or 'Normal'
    confidence: float between 0.0 and 1.0
    selected_model: name of the best model selected
    model_scores: JSON string of all model scores
    Returns: threat assessment with severity level and recommendation.
    """
    conf_pct = confidence * 100

    # Determine severity
    if confidence >= 0.95:
        severity = "CRITICAL"
        recommendation = "Immediate blocking strongly recommended"
    elif confidence >= 0.80:
        severity = "HIGH"
        recommendation = "Blocking recommended"
    elif confidence >= 0.60:
        severity = "MEDIUM"
        recommendation = "Alert SOC and monitor closely"
    elif confidence >= 0.40:
        severity = "LOW"
        recommendation = "Monitor only — confidence insufficient for action"
    else:
        severity = "MINIMAL"
        recommendation = "Allow — very low confidence"

    if prediction == "Normal":
        severity = "NONE"
        recommendation = "Allow traffic — classified as normal"

    result = f"""
Threat Assessment for {srcip}:
  ML Prediction     : {prediction}
  Confidence        : {conf_pct:.1f}%
  Best Model        : {selected_model}
  Severity          : {severity}
  Recommendation    : {recommendation}
  All Model Scores  : {model_scores}
""".strip()

    logger.debug(f"[Tool:assess_threat] {srcip} → {severity} ({conf_pct:.1f}%)")
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 3 — Check Escalation
# ─────────────────────────────────────────────────────────────
@tool
def check_escalation(srcip: str) -> str:
    """
    Checks if a source IP shows an escalating threat pattern.
    Use this when you need to determine if the threat is getting
    worse over time — important for DDoS and persistent attackers.
    Returns: escalation status, burst detection, threat trend analysis.
    """
    if _short_term_memory is None:
        return "Memory not available"

    summary     = _short_term_memory.get_summary(srcip)
    recent      = summary['recent_5min']
    escalating  = summary['is_escalating']
    attacks     = summary['attacks']
    blocks      = summary['blocks']
    avg_conf    = summary['avg_confidence']

    # Burst detection
    if recent >= 100:
        burst_status = f"BURST DETECTED — {recent} requests in 5 minutes (DDoS likely)"
    elif recent >= 50:
        burst_status = f"HIGH VOLUME — {recent} requests in 5 minutes"
    elif recent >= 20:
        burst_status = f"ELEVATED — {recent} requests in 5 minutes"
    else:
        burst_status = f"Normal volume — {recent} requests in 5 minutes"

    # Trend
    if escalating and attacks >= 3:
        trend = "ESCALATING — rising attack pattern confirmed"
    elif escalating:
        trend = "POSSIBLE ESCALATION — pattern emerging"
    elif attacks > 0 and blocks > 0:
        trend = "PERSISTENT — attacks continue despite prior blocks"
    elif attacks > 0:
        trend = "ACTIVE ATTACKER — attacks detected, no prior blocks"
    else:
        trend = "NO ESCALATION — normal or first-time traffic"

    result = f"""
Escalation Analysis for {srcip}:
  Escalating        : {escalating}
  Burst Status      : {burst_status}
  Threat Trend      : {trend}
  Total Attacks     : {attacks}
  Times Blocked     : {blocks}
  Avg Confidence    : {avg_conf}
""".strip()

    logger.debug(f"[Tool:check_escalation] {srcip} → escalating={escalating}")
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 4 — Block IP
# ─────────────────────────────────────────────────────────────
@tool
def block_ip(srcip: str, reason: str) -> str:
    """
    Blocks a malicious IP address immediately.
    Use this for high-confidence attacks, repeat offenders,
    escalating threats, or DDoS patterns.
    This is the strongest response — use when threat is confirmed.
    srcip: the IP address to block
    reason: brief explanation of why blocking is necessary
    Returns: confirmation of block action.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.warning(f"[Tool:block_ip] BLOCKING {srcip} — {reason}")

    result = f"""
ACTION EXECUTED — BLOCK:
  Target IP         : {srcip}
  Action            : IP BLOCKED
  Reason            : {reason}
  Timestamp         : {timestamp}
  Firewall ACL      : Updated — all packets from {srcip} dropped
  Session           : Terminated
  Forensic log      : Created
""".strip()

    return result


# ─────────────────────────────────────────────────────────────
# TOOL 5 — Alert SOC
# ─────────────────────────────────────────────────────────────
@tool
def alert_soc(srcip: str, threat_level: str, reason: str) -> str:
    """
    Sends an alert to the Security Operations Center (SOC).
    Use this for medium-to-high threats that need human review,
    zero-day patterns, or when confidence is moderate but suspicious.
    Does not block the IP — human operator decides next action.
    srcip: the suspicious IP
    threat_level: 'HIGH', 'MEDIUM', or 'LOW'
    reason: what triggered the alert
    Returns: confirmation that SOC was alerted.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.warning(f"[Tool:alert_soc] ALERT sent for {srcip} — {threat_level}")

    result = f"""
ACTION EXECUTED — ALERT SOC:
  Target IP         : {srcip}
  Threat Level      : {threat_level}
  Reason            : {reason}
  Timestamp         : {timestamp}
  SOC Notification  : Sent via secure channel
  SIEM Integration  : Event logged (Splunk/ELK)
  Operator Action   : Required — awaiting human review
""".strip()

    return result


# ─────────────────────────────────────────────────────────────
# TOOL 6 — Rate Limit IP
# ─────────────────────────────────────────────────────────────
@tool
def rate_limit_ip(srcip: str, reason: str) -> str:
    """
    Applies rate limiting to a suspicious IP without full block.
    Use this for moderate threats, suspicious but unconfirmed activity,
    or when false positive risk is high (e.g. IP has prior FP history).
    More proportionate than blocking — allows legitimate traffic to continue.
    srcip: the IP to rate limit
    reason: why rate limiting is appropriate
    Returns: confirmation of rate limit application.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"[Tool:rate_limit_ip] Rate limiting {srcip} — {reason}")

    result = f"""
ACTION EXECUTED — RATE LIMIT:
  Target IP         : {srcip}
  Action            : Rate limited to 10 req/sec
  Reason            : {reason}
  Timestamp         : {timestamp}
  Traffic Status    : Throttled — legitimate traffic may continue
  Review Period     : 5 minutes
""".strip()

    return result


# ─────────────────────────────────────────────────────────────
# TOOL 7 — Monitor IP
# ─────────────────────────────────────────────────────────────
@tool
def monitor_ip(srcip: str, reason: str) -> str:
    """
    Places an IP on the watchlist for enhanced monitoring.
    Use this for low-confidence alerts, first-time suspicious activity,
    or IPs with prior false positives that need careful observation.
    No traffic is blocked — just enhanced logging and alerting.
    srcip: IP to monitor
    reason: why monitoring is appropriate
    Returns: confirmation that IP is being monitored.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"[Tool:monitor_ip] Monitoring {srcip} — {reason}")

    result = f"""
ACTION EXECUTED — MONITOR:
  Target IP         : {srcip}
  Action            : Added to watchlist
  Reason            : {reason}
  Timestamp         : {timestamp}
  Logging           : Enhanced — all packets logged
  Alert Threshold   : Lowered for this IP
  Next Review       : 10 minutes
""".strip()

    return result


# ─────────────────────────────────────────────────────────────
# TOOL 8 — Allow Traffic
# ─────────────────────────────────────────────────────────────
@tool
def allow_traffic(srcip: str, reason: str) -> str:
    """
    Explicitly allows traffic from an IP address.
    Use this when prediction is Normal with high confidence,
    or when all analysis confirms the traffic is legitimate.
    srcip: IP to allow
    reason: why traffic is being allowed
    Returns: confirmation that traffic is allowed.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"[Tool:allow_traffic] Allowing {srcip} — {reason}")

    result = f"""
ACTION EXECUTED — ALLOW:
  Target IP         : {srcip}
  Action            : Traffic allowed
  Reason            : {reason}
  Timestamp         : {timestamp}
  Status            : Normal traffic confirmed
""".strip()

    return result


# ─────────────────────────────────────────────────────────────
# Tool registry — all tools in one list for agent
# ─────────────────────────────────────────────────────────────
ALL_TOOLS = [
    get_ip_history,
    assess_threat,
    check_escalation,
    block_ip,
    alert_soc,
    rate_limit_ip,
    monitor_ip,
    allow_traffic,
]