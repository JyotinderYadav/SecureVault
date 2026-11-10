"""
SecureVault Local SQLite Database Module
Dual-mode query execution for SQL Injection simulation (CWE-89)
"""
import sqlite3
from typing import List, Dict, Any, Optional
from config.settings import DB_PATH
from app.core.auth import hash_password

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    );
    """)

    # 2. Vault records table (Target for SQL Injection CWE-89)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        secret_data TEXT NOT NULL,
        created_by TEXT NOT NULL
    );
    """)

    # 3. Audit logs table (Target for Stored XSS CWE-79)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        comment TEXT NOT NULL,
        content TEXT NOT NULL,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Vault items table (Target for Stage 3 CRUD Producer-Consumer dependencies)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_items (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        owner TEXT NOT NULL
    );
    """)

    # Seed initial data if empty
    cursor.execute("SELECT COUNT(*) FROM users;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin');", (hash_password("adminpass123"),))
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('analyst', ?, 'user');", (hash_password("analystpass"),))

    cursor.execute("SELECT COUNT(*) FROM vault_records;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO vault_records (title, category, secret_data, created_by)
        VALUES ('Cloud Infrastructure Keys', 'Infrastructure', 'SECUREVAULT_FLAG_{SQLI_CWE_89_LEAKED_KEY}', 'admin');
        """)
        cursor.execute("""
        INSERT INTO vault_records (title, category, secret_data, created_by)
        VALUES ('Confidential Master Credentials', 'Security', 'vault_master_secret_token_998877', 'admin');
        """)
        cursor.execute("""
        INSERT INTO vault_records (title, category, secret_data, created_by)
        VALUES ('Database Connection String', 'Database', 'postgres://dbadmin:p@ssw0rd@10.0.0.5:5432/vaultdb', 'analyst');
        """)

    cursor.execute("SELECT COUNT(*) FROM audit_logs;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO audit_logs (title, comment, content, user_agent)
        VALUES ('System Initialization', 'Vault service started', 'Service healthy on localhost', 'SecureVault-Boot/1.0');
        """)

    conn.commit()
    conn.close()

def search_vault_records_vulnerable(query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Intentionally vulnerable SQL query using raw string concatenation (CWE-89).
    Exposes full database records to tautology and UNION injection.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Intentionally vulnerable raw SQL construction
    if category:
        sql = f"SELECT id, title, category, secret_data, created_by FROM vault_records WHERE (title LIKE '%{query}%' OR category = '{category}');"
    else:
        sql = f"SELECT id, title, category, secret_data, created_by FROM vault_records WHERE title LIKE '%{query}%';"
        
    try:
        cursor.execute(sql)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        # Re-raise so the API can surface SQL syntax errors (standard SQLi error signal)
        raise e
    finally:
        conn.close()

def search_vault_records_hardened(query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Hardened SQL query using parameterized execution (removes CWE-89).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if category:
        sql = "SELECT id, title, category, secret_data, created_by FROM vault_records WHERE (title LIKE ? OR category = ?);"
        cursor.execute(sql, (f"%{query}%", category))
    else:
        sql = "SELECT id, title, category, secret_data, created_by FROM vault_records WHERE title LIKE ?;"
        cursor.execute(sql, (f"%{query}%",))
        
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

