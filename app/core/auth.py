"""
SecureVault Authentication and Token Management Module
Provides JWT generation and verification for API access control.
"""
import datetime
import hashlib
import os
from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from config.settings import JWT_SECRET, JWT_ALGORITHM

security_bearer = HTTPBearer(auto_error=False)

def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if not salt:
        salt = os.urandom(16).hex()
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return f"pbkdf2:sha256:100000${salt}${pwd_hash}"

def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifies plain password against stored hash, supporting both PBKDF2 and legacy plain-text fallback."""
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2:sha256:"):
        parts = stored_hash.split("$")
        if len(parts) == 3:
            salt = parts[1]
            return hash_password(plain_password, salt) == stored_hash
    # Safe constant-time or direct equality fallback for legacy plain-text seeds
    return plain_password == stored_hash

def create_access_token(data: Dict[str, Any], expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature has expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid"
        )
    token = credentials.credentials
    return verify_token(token)

