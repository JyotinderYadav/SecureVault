"""
OS Command Injection Router (CWE-78)
Endpoint: POST /api/v1/vault/tools/ping-backup
Simulates host diagnostic and remote backup node connectivity test.
"""
import re
import subprocess
from fastapi import APIRouter, HTTPException, status
from app.models.schemas import PingBackupRequest, PingBackupResponse
from config.settings import system_config

router = APIRouter(prefix="/api/v1/vault/tools", tags=["Command Injection (CWE-78)"])

SAFE_HOST_REGEX = re.compile(r"^[a-zA-Z0-9.\-_:]+$")

@router.post("/ping-backup", response_model=PingBackupResponse, summary="Ping Backup Node (CWE-78 Target)")
def ping_backup_node(payload: PingBackupRequest):
    """
    Test network latency and reachability of a remote vault backup node.
    - VULNERABLE mode: Concatenates input into shell string with shell=True (enables CWE-78).
    - HARDENED mode: Validates host format and invokes command directly with shell=False.
    """
    host_input = payload.host.strip()

    if system_config.is_hardened():
        # HARDENED: Strict alphanumeric hostname/IP validation and prohibit custom commands
        if payload.cmd:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security Policy Violation: Custom command execution is prohibited (CWE-78 mitigation)."
            )
        if not SAFE_HOST_REGEX.match(host_input):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security Policy Violation: Hostname contains invalid shell metacharacters (CWE-78 mitigation)."
            )
        try:
            import sys
            import shutil
            # Safe non-shell execution across Windows and macOS/Linux
            if sys.platform == "win32":
                cmd_args = ["cmd.exe", "/c", f"echo [Vault Ping Tool] Node: {host_input}"]
            else:
                echo_bin = shutil.which("echo") or "/bin/echo"
                cmd_args = [echo_bin, f"[Vault Ping Tool] Node: {host_input}"]

            proc = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
            return PingBackupResponse(
                status="SUCCESS",
                target_host=host_input,
                command_executed=f"echo [Vault Ping Tool] Node: {host_input}",
                output=proc.stdout.strip(),
                exit_code=proc.returncode
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Diagnostic execution error: {str(e)}"
            )
    else:
        # VULNERABLE: Direct shell interpolation allowing command injection via cmd or host
        if payload.cmd:
            cmd_str = f"echo [Vault Ping Tool] Node: {host_input} & {payload.cmd}"
        else:
            cmd_str = f"echo [Vault Ping Tool] Node: {host_input}"

        try:
            proc = subprocess.run(
                cmd_str,
                capture_output=True,
                text=True,
                timeout=5,
                shell=True
            )
            return PingBackupResponse(
                status="SUCCESS",
                target_host=host_input,
                command_executed=cmd_str,
                output=proc.stdout.strip(),
                exit_code=proc.returncode
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Diagnostic command timed out."
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Execution error: {str(e)}"
            )
