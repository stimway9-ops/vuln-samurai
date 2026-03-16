import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sse_starlette.sse import EventSourceResponse

from auth import get_current_user
from database import scans_col
from logger import log_event
from models import ScanRequest
from scanner.engine import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])

def _fmt(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    if "user_id" in doc:
        doc["user_id"] = str(doc["user_id"])
    return doc

# ── Submit scan ────────────────────────────────────────────

@router.post("", status_code=202)
async def submit_scan(
    req: ScanRequest,
    bg: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    doc = {
        "user_id":       ObjectId(user["id"]),
        "target_url":    req.url,
        "status":        "pending",
        "started_at":    None,
        "finished_at":   None,
        "vulnerabilities": [],
        "payloads":      [],
        "summary":       {"high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        "current_engine": None,
        "progress":      0,
        "created_at":    datetime.now(timezone.utc),
    }
    result = await scans_col().insert_one(doc)
    scan_id = str(result.inserted_id)

    await log_event("INFO", f"Scan submitted for {req.url}", user_id=user["id"])

    # Fire and forget — engine writes progress directly to MongoDB
    bg.add_task(run_scan, scan_id, req.url)

    return {"scan_id": scan_id, "status": "pending"}

# ── List scans ─────────────────────────────────────────────

@router.get("")
async def list_scans(user: dict = Depends(get_current_user)):
    cursor = scans_col().find(
        {"user_id": ObjectId(user["id"])},
        {"vulnerabilities": 0, "payloads": 0}   # lightweight list
    ).sort("created_at", -1).limit(50)
    docs = await cursor.to_list(50)
    return [_fmt(d) for d in docs]

# ── Get single scan ────────────────────────────────────────

@router.get("/{scan_id}")
async def get_scan(scan_id: str, user: dict = Depends(get_current_user)):
    doc = await scans_col().find_one({
        "_id":     ObjectId(scan_id),
        "user_id": ObjectId(user["id"])
    })
    if not doc:
        raise HTTPException(404, "Scan not found")
    return _fmt(doc)

# ── Lightweight status poll ────────────────────────────────

@router.get("/{scan_id}/status")
async def scan_status(scan_id: str, user: dict = Depends(get_current_user)):
    doc = await scans_col().find_one(
        {"_id": ObjectId(scan_id), "user_id": ObjectId(user["id"])},
        {"status": 1, "progress": 1, "current_engine": 1}
    )
    if not doc:
        raise HTTPException(404, "Scan not found")
    return {
        "status":         doc["status"],
        "progress":       doc.get("progress", 0),
        "current_engine": doc.get("current_engine"),
    }

# ── SSE live stream ────────────────────────────────────────
# Node.js calls GET /scans/{id}/stream and gets a text/event-stream.
# Each event is a JSON object: {status, progress, current_engine, summary?}

@router.get("/{scan_id}/stream")
async def scan_stream(scan_id: str, user: dict = Depends(get_current_user)):
    async def generator():
        prev_progress = -1
        while True:
            doc = await scans_col().find_one(
                {"_id": ObjectId(scan_id), "user_id": ObjectId(user["id"])},
                {"status": 1, "progress": 1, "current_engine": 1, "summary": 1}
            )
            if not doc:
                yield {"data": json.dumps({"error": "not found"})}
                return

            progress = doc.get("progress", 0)
            if progress != prev_progress:
                prev_progress = progress
                yield {"data": json.dumps({
                    "status":         doc["status"],
                    "progress":       progress,
                    "current_engine": doc.get("current_engine"),
                    "summary":        doc.get("summary", {}),
                })}

            if doc["status"] in ("done", "failed"):
                return

            await asyncio.sleep(1.5)

    return EventSourceResponse(generator())
