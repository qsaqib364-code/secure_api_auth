import asyncio
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from app.config import settings

ph = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
)

DUMMY_HASH = ph.hash("dummy_password_for_timing_protection")

def _hash_sync(password: str) -> str: return ph.hash(password)
def _verify_sync(password: str, hashed: str) -> bool:
    try: return ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError): return False
def _verify_dummy_sync(password: str):
    try: ph.verify(DUMMY_HASH, password)
    except Exception: pass
def _needs_rehash_sync(hashed: str) -> bool: return ph.check_needs_rehash(hashed)

async def hash_password(password: str) -> str:
    return await asyncio.to_thread(_hash_sync, password)
async def verify_password(password: str, hashed: str) -> bool:
    return await asyncio.to_thread(_verify_sync, password, hashed)
async def verify_dummy_password(password: str):
    await asyncio.to_thread(_verify_dummy_sync, password)
async def needs_rehash(hashed: str) -> bool:
    return await asyncio.to_thread(_needs_rehash_sync, hashed)