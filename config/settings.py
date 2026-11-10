"""
SecureVault Configuration Module
"""
import os
import sys
from pathlib import Path

# Ensure matplotlib uses a writable local cache dir
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "app" / "storage" / "uploads"
VAULT_STORAGE = BASE_DIR / "app" / "storage"
DB_PATH = BASE_DIR / "app" / "storage" / "securevault.db"
RESULTS_DIR = BASE_DIR / "results"

# Ensure directories exist (handle read-only filesystems on Streamlit Cloud)
try:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    # Ensure vault secret file exists for path traversal testing
    _secret_path = VAULT_STORAGE / "vault_secret.txt"
    if not _secret_path.exists():
        _secret_path.write_text("VAULT_SECRET_KEY=sv-academic-research-token-2026\n")
except (OSError, PermissionError):
    pass

# ─── Deployment Environment Detection ─────────────────────────────────────────
# Detect Streamlit Cloud / hosted environment (read-only fs, no VULNERABLE mode)
IS_HOSTED = (
    os.environ.get("STREAMLIT_SHARING_MODE") == "streamlit-cloud"
    or os.environ.get("IS_STREAMLIT_CLOUD") == "1"
    or os.environ.get("HOME", "").startswith("/home/appuser")  # Streamlit Cloud default
)

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
        # On hosted/cloud environments always default to HARDENED for safety
        default_mode = "HARDENED" if IS_HOSTED else os.getenv("SECURITY_MODE", "VULNERABLE").upper()
        self._mode: SecurityMode = SecurityMode.HARDENED if default_mode == "HARDENED" else SecurityMode.VULNERABLE

    @property
    def is_hosted(self) -> bool:
        """Returns True when running on Streamlit Cloud or any hosted environment."""
        return IS_HOSTED

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
        if self.is_hosted:
            # Force HARDENED mode in hosted environments for public safety
            self._mode = SecurityMode.HARDENED
            return False
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
        if self.is_hosted:
            self._mode = SecurityMode.HARDENED
            return self._mode.value
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
