"""
Authentication Router
"""
from fastapi import APIRouter, HTTPException, status
from app.models.schemas import LoginRequest, TokenResponse
from app.core.database import get_db_connection
from app.core.auth import create_access_token

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse, summary="User Authentication")
def login(credentials: LoginRequest):
    """
    Authenticate user and generate access token.
    Default admin credentials: admin / adminpass123
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE username = ? AND password = ?;", 
                   (credentials.username, credentials.password))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return TokenResponse(access_token=token, token_type="bearer", role=user["role"])

