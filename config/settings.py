"""
SecureVault Configuration Module
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "app" / "storage" / "uploads"
VAULT_STORAGE = BASE_DIR / "app" / "storage"
DB_PATH = BASE_DIR / "app" / "storage" / "securevault.db"
RESULTS_DIR = BASE_DIR / "results"

# Ensure directories exist
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Default Server Configuration
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", 8000))
API_BASE_URL = f"http://{API_HOST}:{API_PORT}"

# Security Mode State (can be dynamically toggled via /api/v1/system/mode)
class SystemConfig:
    def __init__(self):
        self.security_mode = os.getenv("SECURITY_MODE", "VULNERABLE").upper()

    def set_mode(self, mode: str):
        valid = ["VULNERABLE", "HARDENED"]
        mode_upper = mode.upper()
        if mode_upper in valid:
            self.security_mode = mode_upper
            return True
        return False

    def is_vulnerable(self) -> bool:
        return self.security_mode == "VULNERABLE"

    def is_hardened(self) -> bool:
        return self.security_mode == "HARDENED"

system_config = SystemConfig()
JWT_SECRET = "securevault-cs473-secret-key-2026"
JWT_ALGORITHM = "HS256"
