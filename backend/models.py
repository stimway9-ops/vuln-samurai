from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum

# ── Enums ──────────────────────────────────────────────────

class ScanStatus(str, Enum):
    pending  = "pending"
    running  = "running"
    done     = "done"
    failed   = "failed"

class Severity(str, Enum):
    high   = "High"
    medium = "Medium"
    low    = "Low"
    info   = "Info"

class EventType(str, Enum):
    info  = "INFO"
    warn  = "WARN"
    error = "ERROR"

# ── Auth ───────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=6)

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

# ── Scan ───────────────────────────────────────────────────

class VulnDoc(BaseModel):
    name: str
    severity: Severity
    recommendation: str
    engine: str
    raw: Optional[str] = None

class PayloadDoc(BaseModel):
    vulnerability: str
    payload: str
    result: str
    result_severity: Severity
    description: str
    engine: str

class ScanSummary(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

class ScanRequest(BaseModel):
    url: str
    engines: Optional[List[str]] = None  # None = all engines

class ScanDoc(BaseModel):
    id: Optional[str] = None
    user_id: str
    target_url: str
    status: ScanStatus = ScanStatus.pending
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    vulnerabilities: List[VulnDoc] = []
    payloads: List[PayloadDoc] = []
    summary: ScanSummary = ScanSummary()
    current_engine: Optional[str] = None
    progress: int = 0  # 0-100

class ScanStatusResponse(BaseModel):
    status: ScanStatus
    progress: int
    current_engine: Optional[str] = None

# ── Report ─────────────────────────────────────────────────

class ReportDoc(BaseModel):
    id: Optional[str] = None
    scan_id: str
    user_id: str
    name: str
    generated_at: Optional[datetime] = None
    findings: int = 0
    status: str = "Completed"
    format: str = "json"

# ── Log ────────────────────────────────────────────────────

class LogDoc(BaseModel):
    user_id: Optional[str] = None
    event_type: EventType
    message: str
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Optional[dict] = None
