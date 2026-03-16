from fastapi import APIRouter, HTTPException, Request, status
from datetime import datetime, timezone
from bson import ObjectId

from database import users_col
from models import RegisterRequest, LoginRequest, TokenResponse, RefreshRequest
from auth import (hash_password, verify_password,
                  create_access_token, create_refresh_token, decode_token,
                  get_current_user)
from logger import log_event
from fastapi import Depends

router = APIRouter(prefix="/auth", tags=["auth"])

# ── Register ───────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(req: RegisterRequest, request: Request):
    col = users_col()
    if await col.find_one({"$or": [{"username": req.username}, {"email": req.email}]}):
        raise HTTPException(status_code=409, detail="Username or email already taken")

    doc = {
        "username":      req.username,
        "email":         req.email,
        "password_hash": hash_password(req.password),
        "role":          "analyst",
        "created_at":    datetime.now(timezone.utc),
        "last_login":    None,
        "is_active":     True,
    }
    result = await col.insert_one(doc)
    uid = str(result.inserted_id)
    await log_event("INFO", f"New user registered: {req.username}", user_id=uid,
                    ip_address=request.client.host if request.client else None)
    return {"user_id": uid, "message": "Registered successfully"}

# ── Login ──────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    col = users_col()
    user = await col.find_one({"username": req.username})
    ip = request.client.host if request.client else None

    if not user or not verify_password(req.password, user["password_hash"]):
        await log_event("WARN", f"Failed login: {req.username}", ip_address=ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")

    uid = str(user["_id"])
    await col.update_one({"_id": user["_id"]},
                         {"$set": {"last_login": datetime.now(timezone.utc)}})
    await log_event("INFO", f"Login: {req.username}", user_id=uid, ip_address=ip)

    return TokenResponse(
        access_token=create_access_token(uid),
        refresh_token=create_refresh_token(uid),
    )

# ── Refresh ────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh(req: RefreshRequest):
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    uid = payload["sub"]
    user = await users_col().find_one({"_id": ObjectId(uid)})
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="User not found")
    return TokenResponse(
        access_token=create_access_token(uid),
        refresh_token=create_refresh_token(uid),
    )

# ── Me ─────────────────────────────────────────────────────

@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id":       user["id"],
        "username": user["username"],
        "email":    user["email"],
        "role":     user["role"],
    }
