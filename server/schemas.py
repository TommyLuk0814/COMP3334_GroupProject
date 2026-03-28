from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str
    password: str


class RegisterResponse(BaseModel):
    otp_secret: str
    contact_code: str


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


class MeResponse(BaseModel):
    username: str
    device_id: str
    contact_code: str


class FriendRequestSendRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=128)


class FriendRequestSendResponse(BaseModel):
    id: int
    to_username: str
    status: str


class FriendRequestEntry(BaseModel):
    id: int
    counterparty_username: str
    created_at: datetime


class FriendRequestListResponse(BaseModel):
    requests: List[FriendRequestEntry]


class FriendRequestActionResponse(BaseModel):
    id: int
    status: str


class FriendEntry(BaseModel):
    username: str
    friends_since: datetime


class FriendsListResponse(BaseModel):
    friends: List[FriendEntry]
