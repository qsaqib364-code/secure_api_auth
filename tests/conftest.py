import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch
from app.main import app
from app.database import Base, engine

@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    # Test shuru hone se pehle tables banao
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Test khatam hone ke baad tables drop kar do
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose() # Connections ko cleanly close karo

@pytest.fixture(scope="session")
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

# Email bhejne ko mock karo (taake asli email na jaye)
@pytest.fixture(autouse=True)
def mock_send_email():
    with patch("app.services.auth_service.send_otp_email") as mock_otp, \
         patch("app.services.auth_service.send_security_alert_email") as mock_alert:
        yield mock_otp, mock_alert