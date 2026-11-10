"""
SecureVault Configuration Module
"""
import os
from pathlib import Path

# Ensure matplotlib uses a writable local cache dir
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

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

from enum import Enum
from typing import Union

class SecurityMode(str, Enum):
    VULNERABLE = "VULNERABLE"
    HARDENED = "HARDENED"

# Security Mode State (can be dynamically toggled via /api/v1/system/mode or UI)
class SystemConfig:
    def __init__(self):
        initial_mode = os.getenv("SECURITY_MODE", "VULNERABLE").upper()
        self._mode: SecurityMode = SecurityMode.HARDENED if initial_mode == "HARDENED" else SecurityMode.VULNERABLE

    @property
    def mode(self) -> SecurityMode:
        """Returns the SecurityMode enum instance."""
        return self._mode

    @property
    def security_mode(self) -> str:
        """String representation of security mode for backward compatibility."""
        return self._mode.value

    @security_mode.setter
    def security_mode(self, val: str):
        self.set_mode(val)

    def set_mode(self, mode: Union[SecurityMode, str]) -> bool:
        """Sets the system security mode, accepting either string or SecurityMode."""
        if isinstance(mode, SecurityMode):
            self._mode = mode
            return True
        mode_upper = str(mode).upper()
        if mode_upper in ("VULNERABLE", "HARDENED"):
            self._mode = SecurityMode(mode_upper)
            return True
        return False

    def toggle_mode(self) -> str:
        """Toggles between VULNERABLE and HARDENED mode and returns the new mode string."""
        if self._mode == SecurityMode.VULNERABLE:
            self._mode = SecurityMode.HARDENED
        else:
            self._mode = SecurityMode.VULNERABLE
        return self._mode.value

    def is_vulnerable(self) -> bool:
        return self._mode == SecurityMode.VULNERABLE

    def is_hardened(self) -> bool:
        return self._mode == SecurityMode.HARDENED

system_config = SystemConfig()
JWT_SECRET = os.getenv("JWT_SECRET", "securevault-cs473-secret-key-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
