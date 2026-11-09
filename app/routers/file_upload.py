"""
Unrestricted File Upload Router (CWE-434)
Endpoint: POST /api/v1/vault/upload
Simulates document and archive upload into vault storage.
"""
import os
import uuid
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from app.models.schemas import UploadResponse
from config.settings import STORAGE_DIR, system_config

router = APIRouter(prefix="/api/v1/vault", tags=["Unrestricted File Upload (CWE-434)"])

DANGEROUS_EXTENSIONS = {".php", ".jsp", ".asp", ".aspx", ".py", ".sh", ".exe", ".bat", ".cmd", ".cgi", ".pl"}
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".json", ".csv"}

@router.post("/upload", response_model=UploadResponse, summary="Upload Vault Asset (CWE-434 Target)")
async def upload_vault_file(file: UploadFile = File(..., description="File to store in vault storage")):
    """
    Store files in the vault storage directory.
    - VULNERABLE mode: Preserves client filename and allows arbitrary extensions (enables CWE-434).
    - HARDENED mode: Whitelists extensions, rejects scripts/binaries, and randomizes filenames.
    """
    filename = os.path.basename(file.filename or "unknown")
    ext = Path(filename).suffix.lower()

    # In HARDENED mode, enforce strict extension whitelisting
    if system_config.is_hardened():
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security Policy Violation: Upload of '{ext}' files is prohibited. Allowed: {sorted(list(ALLOWED_EXTENSIONS))}"
            )
        # Generate safe random filename
        safe_filename = f"{uuid.uuid4().hex}{ext}"
        destination = STORAGE_DIR / safe_filename
    else:
        # VULNERABLE: Direct preservation of potentially malicious extension
        destination = STORAGE_DIR / filename

    content = await file.read()
    size_bytes = len(content)

    if size_bytes > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds maximum permissible size (5MB)"
        )

    with open(destination, "wb") as f:
        f.write(content)

    is_exec = ext in DANGEROUS_EXTENSIONS
    warning = "CWE-434: Dangerous executable script stored in vault upload root" if is_exec else None

    return UploadResponse(
        status="STORED",
        filename=destination.name,
        saved_path=f"/storage/uploads/{destination.name}",
        content_type=file.content_type or "application/octet-stream",
        size_bytes=size_bytes,
        is_executable=is_exec,
        warning=warning
    )

