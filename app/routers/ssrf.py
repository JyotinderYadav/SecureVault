"""
SSRF Router (CWE-918)
Endpoint: POST /api/v1/vault/sync
Simulates remote vault synchronization via HTTP proxy / fetch.
"""
import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, HTTPException, status
from app.models.schemas import SyncRequest, SyncResponse
from config.settings import system_config

router = APIRouter(prefix="/api/v1/vault", tags=["SSRF Simulation (CWE-918)"])

def is_ip_forbidden(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or str(ip) == "169.254.169.254"
        )
    except ValueError:
        return True

@router.post("/sync", response_model=SyncResponse, summary="Synchronize Remote Vault (CWE-918 Target)")
def sync_remote_vault(payload: SyncRequest):
    """
    Fetch data from remote vault endpoint to synchronize configurations.
    - VULNERABLE mode: Directly fetches the target URL without validating destination IP (enables SSRF).
    - HARDENED mode: Resolves host, blocks loopback, private ranges, and cloud metadata endpoints.
    """
    target_url = payload.url.strip()
    parsed = urlparse(target_url)

    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported URL scheme. Only HTTP and HTTPS are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid destination URL host."
        )

    # In HARDENED mode, perform strict IP resolution and blocking
    if system_config.is_hardened():
        try:
            resolved_ip = socket.gethostbyname(hostname)
            if is_ip_forbidden(resolved_ip):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Security Policy Violation: Access to private or loopback IP ({resolved_ip}) is blocked."
                )
        except socket.gaierror:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not resolve destination hostname: {hostname}"
            )

    # In VULNERABLE mode, if targeting the simulated internal health service
    if system_config.is_vulnerable() and target_url.endswith("/api/v1/internal/health"):
        return SyncResponse(
            status="SUCCESS",
            target_url=target_url,
            fetched_bytes=142,
            content_preview='{"service": "VaultInternalKeyReleaseService", "status": "ONLINE", "internal_flag": "SECUREVAULT_FLAG_{SSRF_CWE_918_VERIFIED}"}',
            cwe_detected="CWE-918: Server-Side Request Forgery Triggered"
        )

    # Execute synchronization request
    try:
        with httpx.Client(timeout=payload.timeout, follow_redirects=False) as client:
            resp = client.get(target_url)
            content_preview = resp.text[:500]
            fetched_bytes = len(resp.content)
            
            cwe_tag = None
            if system_config.is_vulnerable() and ("127.0.0.1" in target_url or "localhost" in target_url or "169.254" in target_url):
                cwe_tag = "CWE-918: Server-Side Request Forgery Triggered"

            return SyncResponse(
                status="SUCCESS",
                target_url=target_url,
                fetched_bytes=fetched_bytes,
                content_preview=content_preview,
                cwe_detected=cwe_tag
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Remote sync connection failed: {str(exc)}"
        )
