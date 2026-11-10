"""
Automated Integration Tests for SecureVault REST API
Tests all 6 CWE endpoints in both VULNERABLE and HARDENED modes.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from config.settings import system_config

client = TestClient(app)

def test_health_endpoints():
    r1 = client.get("/api/v1/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "HEALTHY"

    r2 = client.get("/api/v1/internal/health")
    assert r2.status_code == 200
    assert "internal_flag" in r2.json()

def test_system_mode_toggle():
    # Toggle to HARDENED
    r = client.post("/api/v1/system/mode", json={"mode": "HARDENED"})
    assert r.status_code == 200
    assert system_config.is_hardened()

    # Toggle to VULNERABLE
    r = client.post("/api/v1/system/mode", json={"mode": "VULNERABLE"})
    assert r.status_code == 200
    assert system_config.is_vulnerable()

def test_auth_login():
    # Valid credentials
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpass123"})
    assert r.status_code == 200
    token_data = r.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # Invalid credentials
    r_bad = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert r_bad.status_code == 401

    # Protected endpoint with valid token
    r_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r_me.status_code == 200
    assert r_me.json()["username"] == "admin"

    # Protected endpoint without token
    r_unauth = client.get("/api/v1/auth/me")
    assert r_unauth.status_code == 401

def test_sql_injection_dual_mode():
    # 1. Test in VULNERABLE mode: Tautology should return all records
    system_config.set_mode("VULNERABLE")
    sqli_payload = "1' OR '1'='1' -- "
    r = client.get(f"/api/v1/vault/records/search?query={sqli_payload}")
    assert r.status_code == 200
    # In vulnerable mode, tautology bypass returns multiple confidential records
    assert r.json()["count"] >= 3

    # 2. Test in HARDENED mode: Tautology treated as literal string search
    system_config.set_mode("HARDENED")
    r_hard = client.get(f"/api/v1/vault/records/search?query={sqli_payload}")
    assert r_hard.status_code == 200
    assert r_hard.json()["count"] == 0

def test_path_traversal_dual_mode():
    # 1. Test in VULNERABLE mode: Traversal should reach vault_secret.txt
    system_config.set_mode("VULNERABLE")
    r = client.get("/api/v1/vault/files/read?filename=../vault_secret.txt")
    assert r.status_code == 200
    assert "VAULT_SECRET_KEY" in r.json()["content"]

    # 2. Test in HARDENED mode: Traversal should be blocked with 403 Forbidden
    system_config.set_mode("HARDENED")
    r_hard = client.get("/api/v1/vault/files/read?filename=../vault_secret.txt")
    assert r_hard.status_code == 403

def test_command_injection_dual_mode():
    # 1. Test in VULNERABLE mode: Shell metacharacter chaining should execute
    system_config.set_mode("VULNERABLE")
    payload = "127.0.0.1 & echo VoAPICmdTest"
    r = client.post("/api/v1/vault/tools/ping-backup", json={"host": payload})
    assert r.status_code == 200
    assert "VoAPICmdTest" in r.json()["output"]

    # 2. Test in HARDENED mode: Metacharacters rejected with 400 Bad Request
    system_config.set_mode("HARDENED")
    r_hard = client.post("/api/v1/vault/tools/ping-backup", json={"host": payload})
    assert r_hard.status_code == 400

    # 3. Test in HARDENED mode: Valid host executes safely without shell
    r_valid = client.post("/api/v1/vault/tools/ping-backup", json={"host": "127.0.0.1"})
    assert r_valid.status_code == 200
    assert r_valid.json()["exit_code"] == 0

def test_file_upload_dual_mode():
    # 1. Test in VULNERABLE mode: Dangerous php extension allowed
    system_config.set_mode("VULNERABLE")
    files = {"file": ("test_webshell.php", b"<?php echo 'test'; ?>", "application/x-php")}
    r = client.post("/api/v1/vault/upload", files=files)
    assert r.status_code == 200
    assert r.json()["is_executable"] is True

    # 2. Test in HARDENED mode: Dangerous extension rejected with 400
    system_config.set_mode("HARDENED")
    files = {"file": ("test_webshell.php", b"<?php echo 'test'; ?>", "application/x-php")}
    r_hard = client.post("/api/v1/vault/upload", files=files)
    assert r_hard.status_code == 400

def test_xss_dual_mode():
    xss_payload = "<script>alert('XSS')</script>"
    # 1. Test in VULNERABLE mode: Stored unescaped
    system_config.set_mode("VULNERABLE")
    r = client.post("/api/v1/vault/audit/logs", json={
        "title": "Vulnerable Log",
        "comment": "Testing XSS",
        "content": xss_payload
    })
    assert r.status_code == 200
    assert r.json()["content"] == xss_payload

    # 2. Test in HARDENED mode: HTML entities escaped
    system_config.set_mode("HARDENED")
    r_hard = client.post("/api/v1/vault/audit/logs", json={
        "title": "Hardened Log",
        "comment": "Testing XSS",
        "content": xss_payload
    })
    assert r_hard.status_code == 200
    assert "&lt;script&gt;" in r_hard.json()["content"]

def test_producer_consumer_crud():
    # Test POST /items (Producer) -> outputs 'id'
    r_create = client.post("/api/v1/vault/items", json={
        "name": "TestVaultKey",
        "description": "Verification key"
    })
    assert r_create.status_code == 201
    item_id = r_create.json()["id"]
    assert item_id is not None

    # Test GET /items/{id} (Consumer) -> consumes 'id'
    r_get = client.get(f"/api/v1/vault/items/{item_id}")
    assert r_get.status_code == 200
    assert r_get.json()["name"] == "TestVaultKey"

    # Test DELETE /items/{id} (Terminator)
    r_del = client.delete(f"/api/v1/vault/items/{item_id}")
    assert r_del.status_code == 200

def test_openapi_schema_generated():
    r = client.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert "paths" in schema
    assert "/api/v1/vault/sync" in schema["paths"]
    assert "/api/v1/vault/upload" in schema["paths"]
    assert "/api/v1/vault/files/read" in schema["paths"]
    assert "/api/v1/vault/tools/ping-backup" in schema["paths"]
    assert "/api/v1/vault/records/search" in schema["paths"]
    assert "/api/v1/vault/audit/logs" in schema["paths"]
