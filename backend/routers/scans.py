import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, HTTPException
from sse_starlette.sse import EventSourceResponse

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

# ── Submit scan (no auth required) ────────────────────────────────────────

@router.post("", status_code=202)
async def submit_scan(
    req: ScanRequest,
    bg: BackgroundTasks,
):
    doc = {
        "user_id":       None,  # Anonymous scan
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

    await log_event("INFO", f"Scan submitted for {req.url}", user_id=None)

    # Fire and forget — engine writes progress directly to MongoDB
    bg.add_task(run_scan, scan_id, req.url)

    return {"scan_id": scan_id, "status": "pending"}

# ── List scans (no auth - returns all for now) ─────────────────────────────

@router.get("")
async def list_scans():
    cursor = scans_col().find(
        {},
        {"vulnerabilities": 0, "payloads": 0}
    ).sort("created_at", -1).limit(50)
    docs = await cursor.to_list(50)
    return [_fmt(d) for d in docs]

# ── Get single scan (no auth) ────────────────────────────────────────────

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    doc = await scans_col().find_one({"_id": ObjectId(scan_id)})
    if not doc:
        raise HTTPException(404, "Scan not found")
    return _fmt(doc)

# ── Lightweight status poll (no auth) ───────────────────────────────────

@router.get("/{scan_id}/status")
async def scan_status(scan_id: str):
    doc = await scans_col().find_one(
        {"_id": ObjectId(scan_id)},
        {"status": 1, "progress": 1, "current_engine": 1}
    )
    if not doc:
        raise HTTPException(404, "Scan not found")
    return {
        "status":         doc["status"],
        "progress":       doc.get("progress", 0),
        "current_engine": doc.get("current_engine"),
    }

# ── SSE live stream (no auth) ───────────────────────────────────────────

@router.get("/{scan_id}/stream")
async def scan_stream(scan_id: str):
    async def generator():
        prev_progress = -1
        while True:
            doc = await scans_col().find_one(
                {"_id": ObjectId(scan_id)},
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
