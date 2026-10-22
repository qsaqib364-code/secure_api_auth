import pytest

# Test 1: Naya User Register ho raha hai ya nahi?
async def test_register_user(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "test1@example.com", "password": "Password@123"}
    )
    assert response.status_code == 201
    assert response.json()["message"] == "User registered successfully"

# Test 2: Duplicate Email block ho rahi hai ya nahi?
async def test_register_duplicate_email(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "test1@example.com", "password": "Password@123"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email is already registered."

# Test 3: Galat Password par Login fail hona chahiye
async def test_login_wrong_password(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test1@example.com", "password": "WrongPassword", "device_id": "test-device"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

# Test 4: Naye Device par OTP Trigger hona chahiye
async def test_login_new_device_otp(client, mock_send_email):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test1@example.com", "password": "Password@123", "device_id": "new-device-123"}
    )
    assert response.status_code == 200
    assert response.json()["require_otp"] is True
    
    # Check karo ke email bhejne wala function call hua
    mock_send_email[0].assert_called_once()