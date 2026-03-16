from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

client: AsyncIOMotorClient = None

def get_db():
    return client["vulnsamurai"]

def users_col():   return get_db()["users"]
def scans_col():   return get_db()["scans"]
def reports_col(): return get_db()["reports"]
def logs_col():    return get_db()["audit_logs"]

async def connect():
    global client
    client = AsyncIOMotorClient(settings.mongo_uri)
    await client.admin.command("ping")
    print("[DB] Connected to MongoDB")

async def disconnect():
    global client
    if client:
        client.close()
