from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.database import Base, engine
from app.api.v1 import auth
from app.models import user, session, device, password_reset, security_event

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()

app = FastAPI(title="Secure Auth API", version="1.0.0", lifespan=lifespan)
app.include_router(auth.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok"}