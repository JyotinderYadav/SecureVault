"""
Cross-Site Scripting (XSS) Router (CWE-79)
Endpoints:
  POST /api/v1/vault/audit/logs
  GET  /api/v1/vault/audit/logs
  GET  /api/v1/vault/audit/logs/view (HTML view)
Simulates audit event logging and text display views.
"""
import html
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from app.models.schemas import AuditLogCreate, AuditLogResponse, AuditLogItem
from app.core.database import get_db_connection
from config.settings import system_config

router = APIRouter(prefix="/api/v1/vault/audit", tags=["Cross-Site Scripting (CWE-79)"])

@router.post("/logs", response_model=AuditLogItem, summary="Create Audit Log Entry (CWE-79 Sink)")
def create_audit_log(payload: AuditLogCreate, request: Request):
    """
    Log an administrative audit action.
    - VULNERABLE mode: Stores user payload unescaped and unsanitized.
    - HARDENED mode: Sanitizes and escapes HTML entities before storing.
    """
    user_agent = request.headers.get("user-agent", "Unknown")

    if system_config.is_hardened():
        title = html.escape(payload.title)
        comment = html.escape(payload.comment)
        content = html.escape(payload.content)
    else:
        title = payload.title
        comment = payload.comment
        content = payload.content

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO audit_logs (title, comment, content, user_agent)
    VALUES (?, ?, ?, ?);
    """, (title, comment, content, user_agent))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return AuditLogItem(
        id=new_id,
        title=title,
        comment=comment,
        content=content,
        user_agent=user_agent
    )

@router.get("/logs", response_model=AuditLogResponse, summary="Retrieve Audit Logs JSON (CWE-79 Target)")
def list_audit_logs():
    """
    List all stored audit log entries in JSON format.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, comment, content, user_agent, timestamp FROM audit_logs ORDER BY id DESC LIMIT 50;")
    rows = cursor.fetchall()
    conn.close()

    items = [
        AuditLogItem(
            id=r["id"],
            title=r["title"],
            comment=r["comment"],
            content=r["content"],
            user_agent=r["user_agent"],
            timestamp=str(r["timestamp"])
        )
        for r in rows
    ]
    return AuditLogResponse(status="SUCCESS", total_logs=len(items), logs=items)

@router.get("/logs/view", response_class=HTMLResponse, summary="Render HTML Audit View (Stored XSS Trigger)")
def view_audit_logs_html():
    """
    Render a server-side HTML administrative dashboard.
    - VULNERABLE mode: Directly concatenates raw content strings into HTML document.
    - HARDENED mode: Strictly escapes all user-supplied text nodes.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, comment, content, user_agent, timestamp FROM audit_logs ORDER BY id DESC LIMIT 20;")
    rows = cursor.fetchall()
    conn.close()

    entries_html = ""
    for r in rows:
        if system_config.is_hardened():
            t = html.escape(r["title"])
            c = html.escape(r["comment"])
            body = html.escape(r["content"])
        else:
            t = r["title"]
            c = r["comment"]
            body = r["content"]

        entries_html += f"""
        <div class="log-card" style="border:1px solid #334155; margin:10px 0; padding:12px; border-radius:6px; background:#0f172a;">
            <div style="font-weight:bold; color:#38bdf8;">Log #{r['id']} — {t}</div>
            <div style="color:#94a3b8; font-size:13px;">Comment: {c}</div>
            <div style="margin-top:8px; color:#f8fafc;">Content: {body}</div>
            <div style="color:#64748b; font-size:11px; margin-top:4px;">Recorded: {r['timestamp']}</div>
        </div>
        """

    html_page = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureVault Audit Dashboard</title>
        <style>body {{ font-family: -apple-system, sans-serif; background: #020617; color: #f8fafc; padding: 24px; }}</style>
    </head>
    <body>
        <h2>SecureVault Audit & Compliance Console</h2>
        <p>Security Mode: <strong>{system_config.security_mode}</strong></p>
        <div class="container">{entries_html}</div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_page)
