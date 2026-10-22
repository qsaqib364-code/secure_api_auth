import uuid
import random
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from app.models.user import User
from app.models.session import Session
from app.models.device import Device
from app.models.password_reset import PasswordResetToken
from app.models.security_event import SecurityEvent
from app.core.security import verify_password, verify_dummy_password, hash_password, needs_rehash
from app.core.jwt_handler import create_refresh_token, hash_refresh_token, verify_access_token
from app.core.email_sender import send_otp_email, send_password_reset_email, send_security_alert_email

INVALID_CREDENTIALS = "Invalid credentials"
RATE_LIMIT_ERROR = "Too many failed attempts. Please try again after 15 minutes."

# --- Token Blacklist Function ---
async def blacklist_token(redis_client: redis.Redis, token: str):
    payload = verify_access_token(token)
    if not payload: return
    
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp: return

    now = datetime.now(timezone.utc).timestamp()
    ttl = int(exp - now)
    
    if ttl > 0:
        # FIX: setex ki jagah set(ex=ttl) use kiya hai
        await redis_client.set(f"blacklist:{jti}", "1", ex=ttl)
        print(f"🚫 Token {jti} blacklisted for {ttl} seconds.")

async def log_security_event(
    db: AsyncSession, user_id: int | None, event_type: str, risk_level: str, 
    ip: str = None, ua: str = None, details: str = None, 
    send_alert: bool = False, email: str = None
):
    event = SecurityEvent(
        user_id=user_id, event_type=event_type, risk_level=risk_level,
        ip_address=ip, user_agent=ua, details=details
    )
    db.add(event)
    await db.commit()

    if send_alert and email:
        await send_security_alert_email(email, event_type, ip or "Unknown", ua or "Unknown")

async def register_user(db: AsyncSession, email: str, password: str):
    result = await db.execute(select(User).where(User.email == email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        return None, "Email is already registered."
    new_user = User(email=email, password_hash=await hash_password(password), is_active=1)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user, ""

async def authenticate_user(db: AsyncSession, redis_client: redis.Redis, email: str, password: str):
    redis_key = f"login_attempts:{email}"
    attempts = await redis_client.get(redis_key)
    if attempts and int(attempts) >= 5:
        return None, RATE_LIMIT_ERROR, 429

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        await verify_dummy_password(password)
        await _handle_failed_attempt(redis_client, redis_key)
        return None, INVALID_CREDENTIALS, 401

    is_valid = await verify_password(password, user.password_hash)
    if not is_valid:
        await _handle_failed_attempt(redis_client, redis_key)
        await log_security_event(db, user.id, "Login Failed", "Medium", details="Wrong password")
        return None, INVALID_CREDENTIALS, 401

    await redis_client.delete(redis_key)
    if await needs_rehash(user.password_hash):
        user.password_hash = await hash_password(password)
        await db.commit()
        await db.refresh(user)
    if not user.is_active:
        return None, INVALID_CREDENTIALS, 401
    return user, "", 200

async def _handle_failed_attempt(redis_client: redis.Redis, redis_key: str):
    current_attempts = await redis_client.incr(redis_key)
    if current_attempts == 1:
        await redis_client.expire(redis_key, 900)

async def create_session_and_tokens(db: AsyncSession, user: User, client_ip: str = None, user_agent: str = None) -> tuple[str, str]:
    session_id = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    refresh_token = create_refresh_token()
    
    new_session = Session(
        id=session_id, user_id=user.id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        family_id=family_id, expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        ip_address=client_ip, user_agent=user_agent
    )
    db.add(new_session)
    await db.commit()
    return session_id, refresh_token

async def rotate_refresh_token(db: AsyncSession, old_refresh_token: str, client_ip: str = None, user_agent: str = None):
    token_hash = hash_refresh_token(old_refresh_token)
    result = await db.execute(select(Session).where(Session.refresh_token_hash == token_hash))
    session = result.scalar_one_or_none()
    
    if not session: return None
    if session.is_revoked:
        await db.execute(update(Session).where(Session.family_id == session.family_id).values(is_revoked=True))
        await db.commit()
        return None
    if session.expires_at < datetime.now(timezone.utc): return None 
        
    session.is_revoked = True
    new_session_id = str(uuid.uuid4())
    new_refresh_token = create_refresh_token()
    
    db.add(Session(
        id=new_session_id, user_id=session.user_id,
        refresh_token_hash=hash_refresh_token(new_refresh_token),
        family_id=session.family_id, expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        ip_address=client_ip, user_agent=user_agent
    ))
    
    user_result = await db.execute(select(User).where(User.id == session.user_id))
    user = user_result.scalar_one()
    await db.commit()
    return user, new_session_id, new_refresh_token

async def revoke_session(db: AsyncSession, session_id: str):
    await db.execute(update(Session).where(Session.id == session_id).values(is_revoked=True))
    await db.commit()

async def revoke_all_sessions(db: AsyncSession, user_id: int):
    await db.execute(update(Session).where(Session.user_id == user_id).values(is_revoked=True))
    await db.commit()

async def is_session_active(db: AsyncSession, session_id: str) -> bool:
    result = await db.execute(select(Session).where(Session.id == session_id))
    session = result.scalar_one_or_none()
    if not session or session.is_revoked or session.expires_at < datetime.now(timezone.utc): return False
    return True

async def get_session(db: AsyncSession, session_id: str) -> Session | None:
    result = await db.execute(select(Session).where(Session.id == session_id))
    return result.scalar_one_or_none()

async def handle_device_and_login(db: AsyncSession, redis_client: redis.Redis, user: User, device_id: str, current_ip: str, current_ua: str) -> tuple[str, str, bool]:
    dev_result = await db.execute(select(Device).where(Device.user_id == user.id, Device.device_id == device_id))
    device = dev_result.scalar_one_or_none()
    
    if not device:
        db.add(Device(user_id=user.id, device_id=device_id, is_trusted=False, ip_address=current_ip, user_agent=current_ua))
        await db.commit()
        await log_security_event(db, user.id, "New Device Detected", "Medium", current_ip, current_ua, details=f"Device: {device_id}")
        await generate_and_send_otp(redis_client, user.email, device_id)
        return "", "", True 
        
    if device.is_trusted:
        if device.ip_address != current_ip or device.user_agent != current_ua:
            device.is_trusted = False
            device.ip_address = current_ip
            device.user_agent = current_ua
            await db.commit()
            await log_security_event(db, user.id, "Suspicious Login (IP/UA Change)", "High", current_ip, current_ua, details=f"Device: {device_id}", send_alert=True, email=user.email)
            await generate_and_send_otp(redis_client, user.email, device_id)
            return "", "", True 
            
    if not device.is_trusted:
        device.ip_address = current_ip
        device.user_agent = current_ua
        await db.commit()
        await generate_and_send_otp(redis_client, user.email, device_id)
        return "", "", True 

    session_id, refresh_token = await create_session_and_tokens(db, user, current_ip, current_ua)
    await log_security_event(db, user.id, "Login Success", "Low", current_ip, current_ua, details=f"Device: {device_id}")
    return session_id, refresh_token, False

async def generate_and_send_otp(redis_client: redis.Redis, email: str, device_id: str):
    cooldown_key = f"otp_cooldown:{email}:{device_id}"
    if await redis_client.get(cooldown_key): return False
    otp_code = str(random.randint(100000, 999999))
    
    # FIX: setex ki jagah set(ex=...) use kiya hai
    await redis_client.set(f"otp:{email}:{device_id}", otp_code, ex=300)
    await redis_client.set(cooldown_key, "1", ex=60)
    
    await redis_client.delete(f"otp_attempts:{email}:{device_id}")
    await send_otp_email(email, otp_code)
    return True

async def verify_otp_and_trust_device(db: AsyncSession, redis_client: redis.Redis, email: str, device_id: str, otp_code: str, current_ip: str = None, current_ua: str = None):
    otp_key = f"otp:{email}:{device_id}"
    attempts_key = f"otp_attempts:{email}:{device_id}"
    saved_otp = await redis_client.get(otp_key)
    
    if not saved_otp: return False, "OTP expired or not found. Please request a new one."
    attempts = await redis_client.get(attempts_key)
    if attempts and int(attempts) >= 3:
        await redis_client.delete(otp_key)
        return False, "Too many failed attempts. Please request a new OTP."

    if saved_otp != otp_code:
        current_attempts = await redis_client.incr(attempts_key)
        if current_attempts == 1: await redis_client.expire(attempts_key, 300)
        return False, f"Invalid OTP. Attempts left: {3 - current_attempts}"
        
    await redis_client.delete(otp_key)
    await redis_client.delete(attempts_key)
    
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user: return False, "User not found"
        
    dev_result = await db.execute(select(Device).where(Device.user_id == user.id, Device.device_id == device_id))
    device = dev_result.scalar_one_or_none()
    
    if device:
        device.is_trusted = True
        if current_ip: device.ip_address = current_ip
        if current_ua: device.user_agent = current_ua
    else:
        db.add(Device(user_id=user.id, device_id=device_id, is_trusted=True, ip_address=current_ip, user_agent=current_ua))
    await db.commit()
    await log_security_event(db, user.id, "Device Verified", "Low", current_ip, current_ua, details=f"Device: {device_id}")
    return True, "Success"

async def request_password_reset(db: AsyncSession, email: str):
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user: return True
    raw_token = secrets.token_urlsafe(16)
    db.add(PasswordResetToken(
        user_id=user.id, token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
    ))
    await db.commit()
    await send_password_reset_email(email, raw_token)
    return True

async def reset_password(db: AsyncSession, email: str, token: str, new_password: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    result = await db.execute(
        select(PasswordResetToken).join(User).where(User.email == email, PasswordResetToken.token_hash == token_hash)
    )
    reset_token = result.scalar_one_or_none()
    if not reset_token or reset_token.is_used or reset_token.expires_at < datetime.now(timezone.utc): return False
        
    user_result = await db.execute(select(User).where(User.id == reset_token.user_id))
    user = user_result.scalar_one()
    user.password_hash = await hash_password(new_password)
    reset_token.is_used = True 
    await revoke_all_sessions(db, user.id)
    await log_security_event(db, user.id, "Password Reset", "High", details="Password was reset via email token")
    await db.commit()
    return True

async def change_password(db: AsyncSession, user_id: int, old_password: str, new_password: str):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user: return "User not found"
    if not await verify_password(old_password, user.password_hash): return "Incorrect old password"
    user.password_hash = await hash_password(new_password)
    await revoke_all_sessions(db, user.id)
    await log_security_event(db, user.id, "Password Changed", "Medium", details="User changed password")
    await db.commit()
    return "Success"