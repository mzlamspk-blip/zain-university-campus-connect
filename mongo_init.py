"""Create the MongoDB collections and indexes used by Campus Connect.

Run once against your database:

    python mongo_init.py

It is idempotent: existing collections/indexes are left untouched.
"""
from pymongo import MongoClient, ASCENDING

from config import Config

client = MongoClient(Config.MONGODB_URI, serverSelectionTimeoutMS=10000)
db = client[Config.MONGODB_DB]

db["students"].create_index([("username", ASCENDING)], unique=True)
db["students"].create_index([("email", ASCENDING)], unique=True)
db["students"].create_index([("student_id", ASCENDING)], unique=True,
                            partialFilterExpression={"student_id": {"$type": "string"}})
db["students"].create_index([("full_name", ASCENDING)])
db["students"].create_index([("department", ASCENDING)])

db["admins"].create_index([("username", ASCENDING)], unique=True)
db["admins"].create_index([("email", ASCENDING)], unique=True)

db["complaints"].create_index([("student_id", ASCENDING)])
db["complaints"].create_index([("status", ASCENDING)])
db["complaints"].create_index([("category", ASCENDING)])
db["complaints"].create_index([("created_at", ASCENDING)])

db["complaint_updates"].create_index([("complaint_id", ASCENDING)])
db["events"].create_index([("event_date", ASCENDING)])
db["event_registrations"].create_index(
    [("event_id", ASCENDING), ("student_id", ASCENDING)], unique=True)

db["lost_found"].create_index([("student_id", ASCENDING)])
db["lost_found"].create_index([("item_name", ASCENDING)])

db["posts"].create_index([("status", ASCENDING)])
db["posts"].create_index([("created_at", ASCENDING)])
db["comments"].create_index([("post_id", ASCENDING)])
db["post_votes"].create_index(
    [("post_id", ASCENDING), ("student_id", ASCENDING), ("vote_type", ASCENDING)],
    unique=True)
db["post_reports"].create_index(
    [("post_id", ASCENDING), ("student_id", ASCENDING)], unique=True)

db["notifications"].create_index([("student_id", ASCENDING), ("is_read", ASCENDING)])

print(f"MongoDB ready: database '{Config.MONGODB_DB}' has all collections and indexes.")
client.close()
