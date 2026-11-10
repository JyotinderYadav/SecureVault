"""
Authentication Router
"""
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends, status
from app.models.schemas import LoginRequest, TokenResponse
from app.core.database import get_db_connection
from app.core.auth import create_access_token, verify_password, get_current_user

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse, summary="User Authentication")
def login(credentials: LoginRequest):
    """
    Authenticate user and generate access token.
    Default admin credentials: admin / adminpass123
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?;", 
                   (credentials.username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return TokenResponse(access_token=token, token_type="bearer", role=user["role"])

@router.get("/me", summary="Get Current Authenticated User (Protected Endpoint)")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Protected endpoint enforcing JWT bearer token authentication.
    """
    return {
        "status": "AUTHENTICATED",
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }

