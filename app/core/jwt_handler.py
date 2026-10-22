import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.core.redis_client import get_redis # <-- Import kiya
import redis.asyncio as redis # <-- Import kiya
import secrets
import hashlib
import uuid # <-- Import kiya

security = HTTPBearer()

def create_refresh_token() -> str:
    return secrets.token_urlsafe(64)

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    
    # NAYA: Har token ke liye unique JTI (JWT ID) generate karo
    to_encode.update({"jti": str(uuid.uuid4())})
    
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# NAYA: Yahan Redis inject kiya hai taake Blacklist check ho sake
async def get_current_user_info(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    redis_client: redis.Redis = Depends(get_redis)
) -> dict:
    token = credentials.credentials
    payload = verify_access_token(token)
    
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    
    # NAYA: Blacklist Check
    jti = payload.get("jti")
    if jti:
        is_blocked = await redis_client.get(f"blacklist:{jti}")
        if is_blocked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been blacklisted. Please login again.")
    
    user_id = payload.get("sub")
    session_id = payload.get("session_id")
    
    if not user_id or not session_id:
        raise HTTPException(status_code=401, detail="Token missing required claims")
        
    return {"user_id": user_id, "session_id": session_id}