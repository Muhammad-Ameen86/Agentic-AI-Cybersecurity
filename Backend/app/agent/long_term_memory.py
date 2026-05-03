import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger("sentinel.long_term_memory")

class LongTermMemory:
    """
    Persistent agent memory using MongoDB.
    Stores every agent decision for audit, analysis and retraining.
    """

    def __init__(
        self,
        uri:         str = None,
        db_name:     str = "The_Sentinel",
        collection:  str = "decisions",
    ):
        # 1. Resolve URI: Arg > Environment Variable > Localhost Fallback
        self.uri = uri or os.getenv("MONGO_URI")
        if not self.uri:
            self.uri = "mongodb://localhost:27017"
            logger.warning("[LTM] No MONGO_URI found, falling back to localhost")

        self.db_name = db_name
        self.collection_name = collection
        self._connected = False
        self.collection = None
        
        try:
            from pymongo import MongoClient, ASCENDING, DESCENDING
            
            # 2. Initialize Client with timeouts for cloud stability
            self.client = MongoClient(
                self.uri, 
                serverSelectionTimeoutMS=5000, 
                connectTimeoutMS=10000
            )
            self.db         = self.client[self.db_name]
            self.collection = self.db[self.collection_name]

            # 3. Verify connection immediately
            self.client.admin.command('ping')

            # 4. Create indexes for performance
            self.collection.create_index([("srcip", ASCENDING)])
            self.collection.create_index([("timestamp", DESCENDING)])
            self.collection.create_index([("decision", ASCENDING)])

            self._connected = True
            logger.info(f"[LTM] Connected to MongoDB successfully: {self.db_name}")

        except Exception as e:
            self._connected = False
            self.collection = None
            logger.error(f"[LTM] MongoDB connection failed: {e}")
            logger.warning("[LTM] Running without persistent memory (Sentinel will still function)")

    def log_decision(
        self,
        srcip:      str,
        model:      str,
        prediction: str,
        confidence: float,
        decision:   str,
        reason:     str,
        raw_data:   Dict[str, Any],
    ) -> bool:
        if not self._connected or self.collection is None:
            return False

        record = {
            "srcip":      srcip,
            "model":      model,
            "prediction": prediction,
            "confidence": confidence,
            "decision":   decision,
            "reason":     reason,
            "raw_data":   raw_data,
            "timestamp":  datetime.now(timezone.utc),
        }

        try:
            self.collection.insert_one(record)
            return True
        except Exception as e:
            logger.warning(f"[LTM] Failed to log decision: {e}")
            return False

    def get_history(self, srcip: str, limit: int = 100):
        if not self._connected or self.collection is None:
            return []
        try:
            return list(
                self.collection
                .find({"srcip": srcip}, {"_id": 0})
                .sort("timestamp", -1)
                .limit(limit)
            )
        except Exception as e:
            logger.warning(f"[LTM] get_history failed: {e}")
            return []

    def get_all(self, limit: int = 10000):
        if not self._connected or self.collection is None:
            return []
        try:
            return list(
                self.collection
                .find({}, {"_id": 0})
                .sort("timestamp", -1)
                .limit(limit)
            )
        except Exception as e:
            logger.warning(f"[LTM] get_all failed: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        if not self._connected or self.collection is None:
            return {"connected": False}
        try:
            return {
                "connected":       True,
                "total_decisions": self.collection.count_documents({}),
                "total_attacks":   self.collection.count_documents({"prediction": "Attack"}),
                "total_blocked":   self.collection.count_documents({"decision": "BLOCK"}),
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    @property
    def is_connected(self) -> bool:
        return self._connected