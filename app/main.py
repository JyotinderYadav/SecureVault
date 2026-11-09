"""
SecureVault REST API Application Entrypoint
Dual-mode testbed service implementing controlled vulnerabilities for:
  - CWE-918: Server-Side Request Forgery
  - CWE-434: Unrestricted File Upload
  - CWE-22:  Path Traversal
  - CWE-78:  OS Command Injection
  - CWE-89:  SQL Injection
  - CWE-79:  Cross-Site Scripting (XSS)
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from config.settings import system_config
from app.core.database import init_db
from app.models.schemas import ModeToggleRequest, ModeResponse
from app.routers import (
    auth,
    ssrf,
    file_upload,
    path_traversal,
    command_injection,
    sql_injection,
    xss,
    vault_items
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and seed records
    init_db()
    yield

# Ensure database is initialized on import
init_db()

app = FastAPI(
    title="SecureVault REST API",
    description="Dual-Mode (Vulnerable vs. Hardened) Cloud Vault Testbed for VOAPI² Security Testing",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local Streamlit interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register functional and vulnerability routers
app.include_router(auth.router)
app.include_router(ssrf.router)
app.include_router(file_upload.router)
app.include_router(path_traversal.router)
app.include_router(command_injection.router)
app.include_router(sql_injection.router)
app.include_router(xss.router)
app.include_router(vault_items.router)

@app.get("/api/v1/health", tags=["Health & Diagnostics"], summary="Public Service Health")
def public_health():
    """Returns general service health status."""
    return {
        "service": "SecureVault API",
        "status": "HEALTHY",
        "active_security_mode": system_config.security_mode,
        "version": "1.0.0"
    }

@app.get("/api/v1/internal/health", tags=["Health & Diagnostics"], summary="Simulated Internal Health (SSRF Target)")
def internal_health():
    """
    Simulated internal microservice.
    In real cloud architectures, this represents an unauthenticated loopback or link-local service.
    Target for CWE-918 (SSRF).
    """
    return {
        "service": "VaultInternalKeyReleaseService",
        "status": "ONLINE",
        "access": "LOOPBACK_ONLY",
        "cluster_node": "node-alpha-127",
        "internal_flag": "SECUREVAULT_FLAG_{SSRF_CWE_918_VERIFIED}"
    }

@app.get("/api/v1/system/mode", response_model=ModeResponse, tags=["Security Configuration"], summary="Get Active Security Mode")
def get_security_mode():
    """Check whether the API is currently in 'VULNERABLE' or 'HARDENED' mode."""
    return ModeResponse(
        status="ACTIVE",
        active_mode=system_config.security_mode,
        message=f"API is currently operating in {system_config.security_mode} mode."
    )

@app.post("/api/v1/system/mode", response_model=ModeResponse, tags=["Security Configuration"], summary="Toggle Security Mode")
def set_security_mode(payload: ModeToggleRequest):
    """
    Dynamically switch security mode between 'VULNERABLE' and 'HARDENED'.
    Enables instant before-and-after demonstration of attack mitigation.
    """
    success = system_config.set_mode(payload.mode)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mode. Must be either 'VULNERABLE' or 'HARDENED'."
        )
    return ModeResponse(
        status="UPDATED",
        active_mode=system_config.security_mode,
        message=f"System security mode successfully transitioned to {system_config.security_mode}."
    )
