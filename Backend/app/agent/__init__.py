def __init__(
        self,
        uri:         str = None,
        db_name:     str = "The_Sentinel",
        collection:  str = "decisions",
    ):
        # 1. Prioritize Environment Variable for Cloud Deployment
        self.uri = uri or os.getenv("MONGO_URI")
        
        if not self.uri:
            # Fallback for local development only
            self.uri = "mongodb://localhost:27017"
            logger.warning("[LTM] No MONGO_URI found, falling back to localhost")

        self.db_name = db_name
        self.collection_name = collection
        
        try:
            from pymongo import MongoClient, ASCENDING, DESCENDING
            # tlsAllowInvalidCertificates is sometimes needed for certain cloud environments
            self.client = MongoClient(
                self.uri, 
                serverSelectionTimeoutMS=5000, # 5 seconds is better for cloud
                connectTimeoutMS=10000
            )
            self.db         = self.client[db_name]
            self.collection = self.db[collection]

            # Trigger a call to verify connection
            self.client.admin.command('ping')

            # Create indexes
            self.collection.create_index([("srcip", ASCENDING)])
            self.collection.create_index([("timestamp", DESCENDING)])

            self._connected = True
            logger.info(f"[LTM] Connected to MongoDB Atlas/Remote successfully.")

        except Exception as e:
            self._connected = False
            self.collection = None
            logger.error(f"[LTM] MongoDB connection failed: {e}")