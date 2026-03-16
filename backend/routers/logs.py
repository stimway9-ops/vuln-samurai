from bson import ObjectId
from fastapi import APIRouter, Depends, Query

from auth import get_current_user, require_admin
from database import logs_col

router = APIRouter(prefix="/logs", tags=["logs"])

@router.get("")
async def get_logs(
    page:  int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    level: str = Query(None),
    _user: dict = Depends(require_admin),
):
    query = {}
    if level:
        query["event_type"] = level.upper()
    skip = (page - 1) * limit
    cursor = logs_col().find(query).sort("timestamp", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(limit)
    for d in docs:
        d["id"] = str(d.pop("_id"))
        if d.get("user_id"):
            d["user_id"] = str(d["user_id"])
    return docs
