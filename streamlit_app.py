"""
SecureVault: Vulnerability-Oriented Security Testing of RESTful APIs
Streamlit Cloud Deployment Entrypoint
Academic Research & Implementation Project (CS-473 Cloud Security and SRE | IIIT Dharwad)
Inspired by VOAPI² (Wenlong Du et al., USENIX Security 2024)
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Ensure database tables are initialized
try:
    from app.core.database import init_db
    init_db()
except Exception:
    pass

from ui.app import main

if __name__ == "__main__":
    main()
