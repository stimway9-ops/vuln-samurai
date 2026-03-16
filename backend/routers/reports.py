from datetime import datetime, timezone
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from auth import get_current_user
from database import reports_col, scans_col
from logger import log_event

router = APIRouter(prefix="/reports", tags=["reports"])

def _fmt(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    doc["scan_id"]  = str(doc.get("scan_id", ""))
    doc["user_id"]  = str(doc.get("user_id", ""))
    return doc

@router.get("")
async def list_reports(user: dict = Depends(get_current_user)):
    cursor = reports_col().find({"user_id": ObjectId(user["id"])}).sort("generated_at", -1)
    docs = await cursor.to_list(100)
    return [_fmt(d) for d in docs]

@router.post("/{scan_id}", status_code=201)
async def generate_report(scan_id: str, user: dict = Depends(get_current_user)):
    scan = await scans_col().find_one({
        "_id":     ObjectId(scan_id),
        "user_id": ObjectId(user["id"]),
    })
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["status"] != "done":
        raise HTTPException(400, "Scan not completed yet")

    doc = {
        "scan_id":      ObjectId(scan_id),
        "user_id":      ObjectId(user["id"]),
        "name":         f"Report — {scan['target_url']} — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
        "generated_at": datetime.now(timezone.utc),
        "findings":     scan.get("summary", {}).get("total", 0),
        "status":       "Completed",
        "format":       "json",
    }
    result = await reports_col().insert_one(doc)
    await log_event("INFO", f"Report generated for scan {scan_id}", user_id=user["id"])
    return {"report_id": str(result.inserted_id)}

@router.get("/{report_id}")
async def get_report(report_id: str, user: dict = Depends(get_current_user)):
    doc = await reports_col().find_one({
        "_id":     ObjectId(report_id),
        "user_id": ObjectId(user["id"]),
    })
    if not doc:
        raise HTTPException(404, "Report not found")
    return _fmt(doc)
