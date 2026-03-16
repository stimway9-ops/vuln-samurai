from datetime import datetime, timezone
from typing import Optional
from database import logs_col

async def log_event(
    event_type: str,
    message: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    metadata: Optional[dict] = None,
):
    doc = {
        "event_type": event_type,
        "message": message,
        "user_id": user_id,
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc),
        "metadata": metadata or {},
    }
    try:
        await logs_col().insert_one(doc)
    except Exception as e:
        # Never let logging crash the app
        print(f"[LOG ERROR] {e}")
