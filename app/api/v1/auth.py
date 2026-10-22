from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import redis.asyncio as redis

from app.database import get_db
from app.core.redis_client import get_redis
from app.core.jwt_handler import create_access_token, get_current_user_info
from app.schemas.auth import (
    LoginRequest, LoginResponse, RegisterRequest, TokenRefreshRequest, 
    VerifyOTPRequest, ForgotPasswordRequest, ResetPasswordRequest, ChangePasswordRequest, ResendOTPRequest
)
from app.services import auth_service
from app.models.user import User
from app.models.device import Device

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    user, error = await auth_service.register_user(db, payload.email, payload.password)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    return LoginResponse(message="User registered successfully")

@router.post("/login")
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db), redis_client: redis.Redis = Depends(get_redis)):
    user, error, status_code = await auth_service.authenticate_user(db, redis_client, payload.email, payload.password)
    if error:
        raise HTTPException(status_code=status_code, detail=error)
    
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    session_id, refresh_token, require_otp = await auth_service.handle_device_and_login(
        db, redis_client, user, payload.device_id, client_ip, user_agent
    )
    
    if require_otp:
        return {"message": "New device or suspicious activity detected. OTP sent.", "require_otp": True}
    
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "session_id": session_id})
    return LoginResponse(message="Login successful", access_token=access_token, refresh_token=refresh_token, token_type="bearer")

@router.post("/verify-otp", response_model=LoginResponse)
async def verify_otp(payload: VerifyOTPRequest, request: Request, db: AsyncSession = Depends(get_db), redis_client: redis.Redis = Depends(get_redis)):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    is_valid, message = await auth_service.verify_otp_and_trust_device(
        db, redis_client, payload.email, payload.device_id, payload.otp_code, client_ip, user_agent
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)
    
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one()
    
    session_id, refresh_token = await auth_service.create_session_and_tokens(db, user, client_ip, user_agent)
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "session_id": session_id})
    return LoginResponse(message="Device verified and login successful", access_token=access_token, refresh_token=refresh_token, token_type="bearer")

@router.post("/resend-otp")
async def resend_otp(payload: ResendOTPRequest, redis_client: redis.Redis = Depends(get_redis)):
    sent = await auth_service.generate_and_send_otp(redis_client, payload.email, payload.device_id)
    if not sent:
        raise HTTPException(status_code=429, detail="Please wait 60 seconds before requesting a new OTP.")
    return {"message": "A new OTP has been sent to your email."}

@router.post("/refresh")
async def refresh_token(payload: TokenRefreshRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    result = await auth_service.rotate_refresh_token(db, payload.refresh_token, client_ip, user_agent)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid or reused refresh token")
    user, new_session_id, new_refresh_token = result
    new_access_token = create_access_token(data={"sub": str(user.id), "email": user.email, "session_id": new_session_id})
    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

@router.get("/me")
async def read_users_me(
    request: Request, 
    user_info: dict = Depends(get_current_user_info), 
    redis_client: redis.Redis = Depends(get_redis), # <-- NAYA: Redis Add kiya
    db: AsyncSession = Depends(get_db)
):
    is_active = await auth_service.is_session_active(db, user_info["session_id"])
    if not is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or expired.")
    
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    session = await auth_service.get_session(db, user_info["session_id"])
    
    # Token Theft Detect hone par
    if session and (session.ip_address != client_ip or session.user_agent != user_agent):
        await auth_service.revoke_session(db, session.id)
        
        # NAYA: Token ko foran Blacklist karo!
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            await auth_service.blacklist_token(redis_client, token)

        user_result = await db.execute(select(User).where(User.id == int(user_info["user_id"])))
        user = user_result.scalar_one_or_none()
        if user:
            await auth_service.log_security_event(
                db, user.id, "Stolen Token Detected", "Critical", client_ip, user_agent,
                details=f"Session ID: {session.id}", send_alert=True, email=user.email
            )
            
        raise HTTPException(status_code=401, detail="Suspicious activity! Token revoked.")

    result = await db.execute(select(User).where(User.id == int(user_info["user_id"])))
    user = result.scalar_one_or_none()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "email": user.email, "is_active": user.is_active}

@router.post("/logout")
async def logout(user_info: dict = Depends(get_current_user_info), db: AsyncSession = Depends(get_db)):
    await auth_service.revoke_session(db, user_info["session_id"])
    return {"message": "Successfully logged out"}

@router.post("/logout-all")
async def logout_all(user_info: dict = Depends(get_current_user_info), db: AsyncSession = Depends(get_db)):
    await auth_service.revoke_all_sessions(db, int(user_info["user_id"]))
    return {"message": "Successfully logged out from all devices"}

@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    await auth_service.request_password_reset(db, payload.email)
    return {"message": "If the email exists, a reset link has been sent."}

@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    is_valid = await auth_service.reset_password(db, payload.email, payload.token, payload.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    return {"message": "Password reset successful. Please login with new password."}

@router.post("/change-password")
async def change_password(payload: ChangePasswordRequest, user_info: dict = Depends(get_current_user_info), db: AsyncSession = Depends(get_db)):
    result = await auth_service.change_password(db, int(user_info["user_id"]), payload.old_password, payload.new_password)
    if result != "Success":
        raise HTTPException(status_code=400, detail=result)
    return {"message": "Password changed successfully. Please login again on all devices."}