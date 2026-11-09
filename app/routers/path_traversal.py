"""
Path Traversal Router (CWE-22)
Endpoint: GET /api/v1/vault/files/read
Simulates reading and downloading stored files from vault storage.
"""
import os
from pathlib import Path
from fastapi import APIRouter, Query, HTTPException, status
from app.models.schemas import FileReadResponse
from config.settings import STORAGE_DIR, system_config

router = APIRouter(prefix="/api/v1/vault", tags=["Path Traversal (CWE-22)"])

@router.get("/files/read", response_model=FileReadResponse, summary="Read Stored File (CWE-22 Target)")
def read_vault_file(
    filename: str = Query(..., description="Target filename or relative path", examples=["sample.txt"]),
    category: str = Query("documents", description="File category in vault")
):
    """
    Read content of a file from vault storage.
    - VULNERABLE mode: Unsanitized path concatenation allows '../' traversal outside upload root.
    - HARDENED mode: Resolves canonical path and verifies it remains strictly within STORAGE_DIR.
    """
    if system_config.is_hardened():
        # HARDENED: Disallow directory traversal sequences and enforce boundary
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Policy Violation: Path Traversal attempt blocked (CWE-22 mitigation)."
            )
        safe_name = Path(filename).name
        target_path = (STORAGE_DIR / safe_name).resolve()
        storage_canonical = STORAGE_DIR.resolve()

        try:
            target_path.relative_to(storage_canonical)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Policy Violation: Path Traversal attempt blocked (CWE-22 mitigation)."
            )
    else:
        # VULNERABLE: Direct path resolution allowing dot-dot-slash traversal
        # Pathlib's / operator resolves relative tokens like ../
        target_path = (STORAGE_DIR / filename).resolve()

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Requested file not found: {filename}"
        )

    try:
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(10000)  # Max 10KB preview
        size_bytes = os.path.getsize(target_path)

        return FileReadResponse(
            status="SUCCESS",
            requested_path=filename,
            resolved_path=str(target_path.name),
            content=content,
            size_bytes=size_bytes
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading file: {str(e)}"
        )
