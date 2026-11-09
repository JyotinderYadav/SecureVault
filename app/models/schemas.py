"""
SecureVault Pydantic Request and Response Schemas
Semantic field names are aligned with real-world REST APIs and VOAPI² keyword mappings.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

# Authentication
class LoginRequest(BaseModel):
    username: str = Field(..., json_schema_extra={"example": "admin"})
    password: str = Field(..., json_schema_extra={"example": "adminpass123"})

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str

# System Configuration & Mode Toggle
class ModeToggleRequest(BaseModel):
    mode: str = Field(..., description="'VULNERABLE' or 'HARDENED'", json_schema_extra={"example": "HARDENED"})

class ModeResponse(BaseModel):
    status: str
    active_mode: str
    message: str

# CWE-918: SSRF (Proxy / Sync API)
class SyncRequest(BaseModel):
    url: str = Field(..., description="Target URL for remote vault synchronization", json_schema_extra={"example": "http://127.0.0.1:8000/api/v1/internal/health"})
    remote_host: Optional[str] = Field(None, description="Remote host identifier or proxy destination", json_schema_extra={"example": "localhost"})
    timeout: Optional[int] = Field(5, description="Timeout in seconds")

class SyncResponse(BaseModel):
    status: str
    target_url: str
    fetched_bytes: int
    content_preview: str
    cwe_detected: Optional[str] = None

# CWE-434: Unrestricted File Upload
class UploadResponse(BaseModel):
    status: str
    filename: str
    saved_path: str
    content_type: str
    size_bytes: int
    is_executable: bool
    warning: Optional[str] = None

# CWE-22: Path Traversal
class FileReadResponse(BaseModel):
    status: str
    requested_path: str
    resolved_path: str
    content: str
    size_bytes: int

# CWE-78: OS Command Injection
class PingBackupRequest(BaseModel):
    host: str = Field(..., description="Hostname or IP address to verify backup synchronization", json_schema_extra={"example": "127.0.0.1"})
    cmd: Optional[str] = Field(None, description="Optional diagnostic shell command", json_schema_extra={"example": "echo VoAPICmdTest"})

class PingBackupResponse(BaseModel):
    status: str
    target_host: str
    command_executed: str
    output: str
    exit_code: int

# CWE-89: SQL Injection
class RecordItem(BaseModel):
    id: int
    title: str
    category: str
    secret_data: str
    created_by: str

class RecordSearchResponse(BaseModel):
    status: str
    query_executed: str
    count: int
    records: List[RecordItem]

# CWE-79: Cross-Site Scripting (Audit Log)
class AuditLogCreate(BaseModel):
    title: str = Field(..., json_schema_extra={"example": "Security Review"})
    comment: str = Field(..., json_schema_extra={"example": "Routine audit log entry"})
    content: str = Field(..., json_schema_extra={"example": "<script>alert('XSS')</script>"})

class AuditLogItem(BaseModel):
    id: int
    title: str
    comment: str
    content: str
    user_agent: Optional[str] = None
    timestamp: Optional[str] = None

class AuditLogResponse(BaseModel):
    status: str
    total_logs: int
    logs: List[AuditLogItem]

# Producer-Consumer Resource (Stage 3 Sequence Generation)
class VaultItemCreate(BaseModel):
    name: str = Field(..., json_schema_extra={"example": "MasterEncryptionKey"})
    description: str = Field(..., json_schema_extra={"example": "AES-256 primary key"})

class VaultItemResponse(BaseModel):
    id: str
    name: str
    description: str
    owner: str
