from pydantic import BaseModel, EmailStr, Field, field_validator

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., max_length=254)
    password: str = Field(..., min_length=1, max_length=128)
    device_id: str = Field(..., min_length=5)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def reject_blank_password(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Password cannot be blank")
        return v

class LoginResponse(BaseModel):
    message: str
    access_token: str | None = None
    refresh_token: str | None = None 
    token_type: str | None = None
    require_otp: bool | None = None

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    device_id: str
    otp_code: str = Field(..., min_length=6, max_length=6)

class ResendOTPRequest(BaseModel):
    email: EmailStr
    device_id: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)