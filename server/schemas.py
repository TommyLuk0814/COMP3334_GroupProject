from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str
    password: str


class RegisterResponse(BaseModel):
    otp_secret: str


class LoginPasswordRequest(BaseModel):
    username: str
    password: str


class LoginPasswordResponse(BaseModel):
    otp_required: bool = True


class LoginOTPRequest(BaseModel):
    username: str
    password: str
    otp: str
    device_id: str = Field(default="default-device", min_length=4, max_length=128)


class LoginOTPResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class LogoutResponse(BaseModel):
    detail: str


class UploadKeyRequest(BaseModel):
    public_key_pem: str = Field(min_length=32, max_length=10000)


class UploadKeyResponse(BaseModel):
    device_id: str
    fingerprint: str
    updated_at: datetime


class PublicKeyEntry(BaseModel):
    device_id: str
    public_key_pem: str
    fingerprint: str
    updated_at: datetime


class PublicKeysResponse(BaseModel):
    username: str
    keys: List[PublicKeyEntry]
