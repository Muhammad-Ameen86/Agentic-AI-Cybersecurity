import os
from pymongo import MongoClient

# Get Mongo URI from environment
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    print("❌ MONGO_URI not found in environment")
    exit()

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client.get_database("The_Sentinel")

    # Test connection
    client.admin.command("ping")

    print("✅ MongoDB Atlas connected successfully!")

except Exception as e:
    print("❌ MongoDB connection failed:")
    print(e)