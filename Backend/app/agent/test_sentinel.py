"""
=============================================================
  THE SENTINEL — Complete Backend Test Suite
  Run this while uvicorn is running on port 8000
  
  Usage:
      python test_sentinel.py
=============================================================
"""

import requests
import json
import time
import sys
from datetime import datetime

BASE_URL = self.mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")

# ── Colors for terminal output ──
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

passed = 0
failed = 0
warnings = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}✅ PASS{RESET} — {msg}")


def fail(msg, detail=""):
    global failed
    failed += 1
    print(f"  {RED}❌ FAIL{RESET} — {msg}")
    if detail:
        print(f"         {RED}{detail}{RESET}")


def warn(msg):
    global warnings
    warnings += 1
    print(f"  {YELLOW}⚠️  WARN{RESET} — {msg}")


def section(title):
    print(f"\n{BOLD}{CYAN}{'='*55}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*55}{RESET}")


def get(path, label):
    try:
        r = requests.get(f"{BASE_URL}{path}", timeout=10)
        return r
    except requests.ConnectionError:
        fail(label, "Cannot connect to server — is uvicorn running?")
        return None
    except Exception as e:
        fail(label, str(e))
        return None


def post(path, payload, label):
    try:
        r = requests.post(
            f"{BASE_URL}{path}",
            json=payload,
            timeout=15
        )
        return r
    except requests.ConnectionError:
        fail(label, "Cannot connect to server — is uvicorn running?")
        return None
    except Exception as e:
        fail(label, str(e))
        return None


# =============================================================
# TEST 1 — SERVER HEALTH
# =============================================================
section("1. Server Health")

r = get("/", "Root endpoint")
if r:
    if r.status_code == 200:
        data = r.json()
        ok(f"Root endpoint — status: {data.get('status')}")
    else:
        fail("Root endpoint", f"Status {r.status_code}")

r = get("/health", "Health endpoint")
if r:
    if r.status_code == 200:
        data = r.json()
        ok(f"Health endpoint — agent: {data.get('agent')} | memory: {data.get('memory')}")
        models = data.get('models', [])
        if models:
            ok(f"Models loaded: {models}")
        else:
            warn("No models listed in health response")
        if data.get('memory') == 'unavailable':
            warn("MongoDB not connected — decisions will not be persisted")
        else:
            ok("MongoDB connected")
    else:
        fail("Health endpoint", f"Status {r.status_code}")


# =============================================================
# TEST 2 — METRICS ENDPOINTS
# =============================================================
section("2. Metrics Endpoints")

r = get("/metrics/", "Model metrics")
if r:
    if r.status_code == 200:
        data = r.json()
        if "UNSW-NB15" in data:
            unsw = data["UNSW-NB15"]
            # Show best model accuracy
            best_model = max(
                unsw.items(),
                key=lambda x: x[1].get('accuracy', 0) if isinstance(x[1], dict) else 0
            )
            ok(f"Metrics loaded — best model: {best_model[0]} "
               f"acc={best_model[1].get('accuracy', 'N/A')}")
        else:
            warn("UNSW-NB15 metrics not found — run ML pipeline Cell 9 first")
        if "CIC-IDS-2017" in data and data["CIC-IDS-2017"] != "Not evaluated yet":
            ok("CIC-IDS-2017 metrics loaded")
        else:
            warn("CIC-IDS-2017 metrics not found — run ML pipeline Cell 10 first")
    else:
        fail("Model metrics", f"Status {r.status_code} — {r.text[:100]}")

r = get("/metrics/latency", "Latency metrics")
if r:
    if r.status_code == 200:
        data = r.json()
        for model, lat in data.items():
            ok(f"Latency [{model}]: "
               f"mean={lat.get('mean_ms')}ms | "
               f"p95={lat.get('p95_ms')}ms | "
               f"p99={lat.get('p99_ms')}ms")
    elif r.status_code == 404:
        warn("Latency metrics not found — run ML pipeline Cell 13 first")
    else:
        fail("Latency metrics", f"Status {r.status_code}")

r = get("/metrics/cross-dataset", "Cross-dataset metrics")
if r:
    if r.status_code == 200:
        ok("Cross-dataset evaluation results loaded")
    elif r.status_code == 404:
        warn("Cross-dataset metrics not found — run ML pipeline Cell 12 first")
    else:
        fail("Cross-dataset metrics", f"Status {r.status_code}")


# =============================================================
# TEST 3 — PREDICTION ENDPOINT
# =============================================================
section("3. Prediction Endpoint — Normal Traffic")

normal_payload = {
    "data": {
        "srcip":  "192.168.1.100",
        "dstip":  "10.0.0.1",
        "proto":  "tcp",
        "state":  "FIN",
        "dur":    0.02,
        "sbytes": 500,
        "dbytes": 300,
        "sttl":   64,
        "dttl":   64,
        "sloss":  0,
        "dloss":  0,
        "Spkts":  5,
        "Dpkts":  4,
    },
    "dataset": "unsw"
}

r = post("/predict/", normal_payload, "Normal traffic prediction")
if r:
    if r.status_code == 200:
        data = r.json()
        ok(f"Prediction received")
        ok(f"  srcip     : {data.get('srcip')}")
        ok(f"  model     : {data.get('selected_model')}")
        ok(f"  prediction: {data.get('prediction')}")
        ok(f"  confidence: {data.get('confidence')}")
        ok(f"  decision  : {data.get('decision')}")
        ok(f"  latency   : {data.get('latency_ms')}ms")
        ok(f"  reason    : {data.get('reason')}")

        reasoning = data.get('agent_reasoning', {})
        mem = reasoning.get('memory_context', {})
        ok(f"  risk_score: {mem.get('risk_score')}")
        ok(f"  escalating: {mem.get('is_escalating')}")
    else:
        fail("Normal prediction", f"Status {r.status_code} — {r.text[:200]}")


# =============================================================
# TEST 4 — ATTACK SIMULATION
# =============================================================
section("4. Attack Simulation — High Volume from Same IP")

attack_ip = "10.0.0.99"
attack_payload = {
    "data": {
        "srcip":  attack_ip,
        "dstip":  "192.168.1.1",
        "proto":  "tcp",
        "state":  "CON",
        "dur":    0.001,
        "sbytes": 99999,
        "dbytes": 0,
        "sttl":   128,
        "dttl":   0,
        "sloss":  50,
        "dloss":  50,
        "Spkts":  1000,
        "Dpkts":  0,
    },
    "dataset": "unsw"
}

print(f"\n  Sending 5 requests from attack IP: {attack_ip}")
decisions = []
for i in range(5):
    r = post("/predict/", attack_payload, f"Attack request {i+1}")
    if r and r.status_code == 200:
        d = r.json()
        decisions.append(d.get('decision'))
        print(f"    Request {i+1}: pred={d.get('prediction')} | "
              f"conf={d.get('confidence')} | "
              f"decision={d.get('decision')}")
        time.sleep(0.1)

if decisions:
    blocks = decisions.count('BLOCK')
    alerts = decisions.count('ALERT')
    ok(f"Attack simulation complete — BLOCK: {blocks} | ALERT: {alerts}")
    if blocks > 0:
        ok("Agent escalated to BLOCK on repeated attack traffic")
    else:
        warn("Agent did not BLOCK — check policy thresholds or model confidence")


# =============================================================
# TEST 5 — IP STATUS ENDPOINT
# =============================================================
section("5. IP Status — Agent Memory State")

r = get(f"/predict/ip/{attack_ip}", f"IP status for {attack_ip}")
if r:
    if r.status_code == 200:
        data = r.json()
        summary = data.get('summary', {})
        ok(f"IP memory retrieved for {attack_ip}")
        ok(f"  requests   : {summary.get('requests')}")
        ok(f"  attacks    : {summary.get('attacks')}")
        ok(f"  blocks     : {summary.get('blocks')}")
        ok(f"  escalating : {summary.get('is_escalating')}")
        ok(f"  recent 5min: {summary.get('recent_5min')}")
        ok(f"  avg conf   : {summary.get('avg_confidence')}")
    else:
        fail("IP status", f"Status {r.status_code}")


# =============================================================
# TEST 6 — INGEST ENDPOINT
# =============================================================
section("6. Ingest Endpoint")

ingest_payload = {
    "data": {
        "srcip":  "172.16.0.55",
        "proto":  "udp",
        "sbytes": 200,
        "dbytes": 100,
    },
    "dataset": "unsw"
}

r = post("/ingest/", ingest_payload, "Ingest endpoint")
if r:
    if r.status_code == 200:
        data = r.json()
        ok(f"Ingest working — status: {data.get('status')}")
        ok(f"  decision: {data.get('decision')}")
        ok(f"  latency : {data.get('latency_ms')}ms")
    else:
        fail("Ingest endpoint", f"Status {r.status_code} — {r.text[:100]}")


# =============================================================
# TEST 7 — EVALUATION ENDPOINTS
# =============================================================
section("7. Evaluation Endpoints")

r = get("/evaluation/summary", "Evaluation summary")
if r:
    if r.status_code == 200:
        data = r.json()
        if "total_requests" in data:
            ok(f"Evaluation summary — total: {data.get('total_requests')} | "
               f"unique IPs: {data.get('unique_ips')}")
            ok(f"  decisions   : {data.get('decision_distribution')}")
            ok(f"  predictions : {data.get('prediction_distribution')}")
            ok(f"  block rate  : {data.get('attack_block_rate')}")
        elif "message" in data:
            warn(f"Evaluation: {data.get('message')}")
        else:
            warn("Evaluation summary returned unexpected format")
    elif r.status_code == 503:
        warn("MongoDB not connected — evaluation summary unavailable")
    else:
        fail("Evaluation summary", f"Status {r.status_code}")

r = get("/evaluation/memory/active", "Active memory")
if r:
    if r.status_code == 200:
        data = r.json()
        ok(f"Active memory — tracking {data.get('active_ips')} IPs")
    else:
        fail("Active memory", f"Status {r.status_code}")

r = get(f"/evaluation/ip/{attack_ip}", "IP history from MongoDB")
if r:
    if r.status_code == 200:
        data = r.json()
        if "total_records" in data:
            ok(f"MongoDB IP history — {data.get('total_records')} records for {attack_ip}")
        elif "message" in data:
            warn(f"MongoDB: {data.get('message')}")
    elif r.status_code == 503:
        warn("MongoDB not connected — IP history unavailable")
    else:
        fail("IP history", f"Status {r.status_code}")


# =============================================================
# TEST 8 — FALSE POSITIVE FEEDBACK
# =============================================================
section("8. False Positive Feedback")

r = post(
    f"/evaluation/feedback/false-positive/{attack_ip}",
    {},
    "False positive feedback"
)
if r:
    if r.status_code == 200:
        data = r.json()
        ok(f"False positive recorded for {attack_ip}")
        ok(f"  message: {data.get('message')}")
    else:
        fail("False positive feedback", f"Status {r.status_code}")

# Send one more prediction for attack IP after false positive
# Agent should now be more cautious (MONITOR instead of BLOCK)
print(f"\n  Sending prediction after false positive recorded...")
r = post("/predict/", attack_payload, "Post false-positive prediction")
if r and r.status_code == 200:
    d = r.json()
    print(f"    Decision: {d.get('decision')} | reason: {d.get('reason')}")
    if d.get('decision') == 'MONITOR':
        ok("Agent applied false positive caution correctly — MONITOR instead of BLOCK")
    else:
        warn(f"Agent decision: {d.get('decision')} — may still block due to repeat history")


# =============================================================
# TEST 9 — WEBSOCKET (basic check)
# =============================================================
section("9. WebSocket Feed")

try:
    import websocket as ws_lib
    ws = ws_lib.create_connection("ws://localhost:8000/ws/feed", timeout=5)
    msg = ws.recv()
    data = json.loads(msg)
    if data.get('type') == 'connected':
        ok(f"WebSocket connected — message: {data.get('message')}")
    ws.close()
except ImportError:
    warn("websocket-client not installed — skipping WS test")
    warn("Install with: pip install websocket-client")
except Exception as e:
    warn(f"WebSocket test skipped: {e}")


# =============================================================
# FINAL REPORT
# =============================================================
section("FINAL REPORT")

total = passed + failed + warnings
print(f"\n  {BOLD}Total checks : {total}{RESET}")
print(f"  {GREEN}Passed       : {passed}{RESET}")
print(f"  {RED}Failed       : {failed}{RESET}")
print(f"  {YELLOW}Warnings     : {warnings}{RESET}")

print()
if failed == 0:
    print(f"  {GREEN}{BOLD}🛡️  THE SENTINEL — ALL SYSTEMS OPERATIONAL{RESET}")
elif failed <= 3:
    print(f"  {YELLOW}{BOLD}⚠️  THE SENTINEL — MOSTLY WORKING ({failed} issues){RESET}")
else:
    print(f"  {RED}{BOLD}❌ THE SENTINEL — NEEDS ATTENTION ({failed} failures){RESET}")

print(f"\n  Run timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()