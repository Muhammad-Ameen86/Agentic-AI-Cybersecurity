from Backend.app.agent.long_term_memory import LongTermMemory

# Initialize your memory module
memory = LongTermMemory()

# Simulate an AI Agent blocking a malicious IP
success = memory.log_decision(
    srcip="192.168.1.100",
    model="RandomForest_v1",
    prediction="Attack",
    confidence=0.99,
    decision="BLOCK",
    reason="Agentic reasoning: Repeated failed login attempts + matching DDoS signature.",
    raw_data={"packet_count": 500, "protocol": "TCP"}
)

if success:
    print("✅ Success! Your 'The_Sentinel' database will now appear in Atlas.")
else:
    print("❌ Failed. Check your MONGO_URI and Network Access settings.")