from datetime import datetime
from typing import List, Optional

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


class FriendTargetRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=128)


class FriendRemoveResponse(BaseModel):
    username: str


class FriendBlockResponse(BaseModel):
    blocked_username: str


class FriendUnblockResponse(BaseModel):
    unblocked_username: str


class BlockedUsersResponse(BaseModel):
    blocked_users: List[str]


class SessionInitRequest(BaseModel):
    target_username: str = Field(min_length=1, max_length=128)
    target_device_id: str = Field(default="", max_length=128)
    initiator_ephemeral_pub: str = Field(min_length=16, max_length=4096)
    initiator_signature: str = Field(min_length=16, max_length=4096)


class SessionInitResponse(BaseModel):
    handshake_id: int
    recipient_username: str
    recipient_device_id: str
    status: str


class PendingSessionHandshakeEntry(BaseModel):
    id: int
    initiator_username: str
    initiator_device_id: str
    recipient_device_id: str
    initiator_ephemeral_pub: str
    initiator_signature: str
    created_at: datetime


class PendingSessionHandshakeListResponse(BaseModel):
    handshakes: List[PendingSessionHandshakeEntry]


class SessionRespondRequest(BaseModel):
    responder_ephemeral_pub: str = Field(min_length=16, max_length=4096)
    responder_signature: str = Field(min_length=16, max_length=4096)


class SessionRespondResponse(BaseModel):
    handshake_id: int
    status: str


class RespondedSessionHandshakeEntry(BaseModel):
    id: int
    recipient_username: str
    recipient_device_id: str
    initiator_ephemeral_pub: str
    responder_ephemeral_pub: str
    responder_signature: str
    responded_at: datetime


class RespondedSessionHandshakeListResponse(BaseModel):
    handshakes: List[RespondedSessionHandshakeEntry]


class SendMessageRequest(BaseModel):
    recipient_username: str = Field(min_length=1, max_length=128)
    recipient_device_id: str = Field(default="", max_length=128)
    ciphertext: str = Field(min_length=1, max_length=100000)
    nonce: str = Field(min_length=1, max_length=4096)
    aad: str = Field(min_length=1, max_length=20000)
    sender_counter: int = Field(ge=0)
    expires_in_seconds: int = Field(default=0, ge=0, le=86400)


class SendMessageResponse(BaseModel):
    message_id: int
    status: str
    sent_at: datetime


class MessageEnvelope(BaseModel):
    id: int
    sender_username: str
    sender_device_id: str
    recipient_username: str
    recipient_device_id: str
    ciphertext: str
    nonce: str
    aad: str
    sender_counter: int
    created_at: datetime
    expires_at: Optional[datetime] = None


class PollMessagesResponse(BaseModel):
    messages: List[MessageEnvelope]


class MessageAckResponse(BaseModel):
    message_id: int
    status: str


class MessageStatusRequest(BaseModel):
    message_ids: List[int] = Field(default_factory=list, max_length=200)


class MessageStatusEntry(BaseModel):
    message_id: int
    status: str
    delivered_at: Optional[datetime] = None


class MessageStatusResponse(BaseModel):
    statuses: List[MessageStatusEntry]


class PrekeyUploadEntry(BaseModel):
    prekey_id: str = Field(min_length=8, max_length=128)
    prekey_public: str = Field(min_length=16, max_length=4096)
    prekey_signature: str = Field(min_length=16, max_length=4096)


class UploadPrekeysRequest(BaseModel):
    prekeys: List[PrekeyUploadEntry] = Field(default_factory=list, max_length=200)


class UploadPrekeysResponse(BaseModel):
    uploaded: int


class ClaimPrekeyResponse(BaseModel):
    username: str
    device_id: str
    identity_key_pem: str
    prekey_id: str
    prekey_public: str
    prekey_signature: str
