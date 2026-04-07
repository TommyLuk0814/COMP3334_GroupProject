"""FastAPI backend server handling user management, friend relationships, session handshakes, message exchange, and key management with appropriate rate limiting and security checks."""

from datetime import datetime, timedelta
import os
from pathlib import Path
from typing import Dict, Optional
import secrets

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import pyotp
import uvicorn

from config import RATE_LIMITS, SESSION_TTL_HOURS
from database import db
from rate_limiter import RateLimiter
from schemas import (
    FriendBlockResponse,
    FriendUnblockResponse,
    BlockedUsersResponse,
    FriendEntry,
    FriendRemoveResponse,
    FriendRequestActionResponse,
    FriendRequestEntry,
    FriendRequestListResponse,
    FriendRequestSendRequest,
    FriendRequestSendResponse,
    FriendsListResponse,
    FriendTargetRequest,
    LoginOTPRequest,
    LoginOTPResponse,
    LoginPasswordRequest,
    LoginPasswordResponse,
    LogoutResponse,
    MeResponse,
    PublicKeyEntry,
    PublicKeysResponse,
    RegisterRequest,
    RegisterResponse,
    RespondedSessionHandshakeEntry,
    RespondedSessionHandshakeListResponse,
    SessionInitRequest,
    SessionInitResponse,
    SessionRespondRequest,
    SessionRespondResponse,
    PendingSessionHandshakeEntry,
    PendingSessionHandshakeListResponse,
    PollMessagesResponse,
    MessageEnvelope,
    MessageAckResponse,
    MessageStatusRequest,
    MessageStatusResponse,
    MessageStatusEntry,
    UploadKeyRequest,
    UploadKeyResponse,
    SendMessageRequest,
    SendMessageResponse,
    UploadPrekeysRequest,
    UploadPrekeysResponse,
    ClaimPrekeyResponse,
)
from security import (
    client_ip,
    fingerprint_for_pem,
    get_current_session,
    hash_password,
    normalize_username,
    validate_password_policy,
    validate_username,
    verify_password,
)

app = FastAPI(title="Secure IM Backend", version="0.1.0")
rate_limiter = RateLimiter()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest, request: Request):
    ip = client_ip(request)
    normalized_username = normalize_username(req.username)
    rate_limiter.check("register", f"{ip}:{normalized_username}", *RATE_LIMITS["register"])
    validate_username(normalized_username)
    validate_password_policy(req.password)
    if db.get_user(normalized_username):
        raise HTTPException(status_code=400, detail="Username already exists")

    otp_secret = pyotp.random_base32()
    contact_code = db.create_user(normalized_username, hash_password(req.password), otp_secret)
    return RegisterResponse(otp_secret=otp_secret, contact_code=contact_code)


@app.post("/login/password", response_model=LoginPasswordResponse)
def login_password(req: LoginPasswordRequest, request: Request):
    ip = client_ip(request)
    normalized_username = normalize_username(req.username)
    rate_limiter.check("login_password", f"{ip}:{normalized_username}", *RATE_LIMITS["login_password"])

    user = db.get_user(normalized_username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return LoginPasswordResponse(otp_required=True)


@app.post("/login/otp", response_model=LoginOTPResponse)
def login_otp(req: LoginOTPRequest, request: Request):
    ip = client_ip(request)
    normalized_username = normalize_username(req.username)
    rate_limiter.check("login_otp", f"{ip}:{normalized_username}", *RATE_LIMITS["login_otp"])

    user = db.get_user(normalized_username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    totp = pyotp.TOTP(user["otp_secret"])
    if not totp.verify(req.otp, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)
    db.upsert_session(token=token, username=normalized_username, device_id=req.device_id, expires_at=expires_at)
    return LoginOTPResponse(access_token=token, expires_at=expires_at)


@app.post("/logout", response_model=LogoutResponse)
def logout(session: Dict[str, str] = Depends(get_current_session)):
    db.revoke_user_sessions(session["username"])
    return LogoutResponse(detail="Logged out")


def resolve_friend_target_identifier(identifier: str) -> Optional[str]:
    raw = identifier.strip()
    if not raw:
        return None
    by_username = db.get_user(normalize_username(raw))
    if by_username:
        return str(by_username["username"])
    by_code = db.get_user_by_contact_code(raw)
    if by_code:
        return str(by_code["username"])
    return None


def resolve_target_device_id(username: str, preferred_device_id: str) -> Optional[str]:
    rows = db.list_identity_keys(username)
    if not rows:
        return None
    if preferred_device_id:
        for row in rows:
            if row["device_id"] == preferred_device_id:
                return str(row["device_id"])
        return None
    return str(rows[0]["device_id"])


@app.get("/me", response_model=MeResponse)
def me(session: Dict[str, str] = Depends(get_current_session)):
    user = db.get_user(session["username"])
    if not user or not user["contact_code"]:
        raise HTTPException(status_code=500, detail="User profile incomplete")
    return MeResponse(
        username=session["username"],
        device_id=session["device_id"],
        contact_code=str(user["contact_code"]),
    )


@app.post("/friends/request", response_model=FriendRequestSendResponse)
def send_friend_request(
    req: FriendRequestSendRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])

    target = resolve_friend_target_identifier(req.identifier)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    rid, status, err = db.create_or_refresh_friend_request(session["username"], target)
    if err == "cannot_add_self":
        raise HTTPException(status_code=400, detail="Cannot add yourself")
    if err == "already_friends":
        raise HTTPException(status_code=400, detail="Already friends")
    if err == "incoming_pending_exists":
        raise HTTPException(
            status_code=409,
            detail="This user already sent you a request; accept or decline it in Request List",
        )
    if err == "duplicate_pending":
        raise HTTPException(status_code=400, detail="Friend request already sent")
    if err == "blocked":
        raise HTTPException(status_code=403, detail="You cannot interact with this user (blocked)")
    return FriendRequestSendResponse(id=rid, to_username=target, status=status)


@app.get("/friends/requests/incoming", response_model=FriendRequestListResponse)
def list_incoming_friend_requests(session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_incoming_friend_requests(session["username"])
    return FriendRequestListResponse(
        requests=[
            FriendRequestEntry(
                id=int(r["id"]),
                counterparty_username=str(r["from_user"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]
    )


@app.get("/friends/requests/outgoing", response_model=FriendRequestListResponse)
def list_outgoing_friend_requests(session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_outgoing_friend_requests(session["username"])
    return FriendRequestListResponse(
        requests=[
            FriendRequestEntry(
                id=int(r["id"]),
                counterparty_username=str(r["to_user"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]
    )


@app.post("/friends/requests/{request_id}/accept", response_model=FriendRequestActionResponse)
def accept_friend_request(
    request_id: int,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    result = db.accept_friend_request(request_id, session["username"])
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Request not found")
    if result == "forbidden":
        raise HTTPException(status_code=403, detail="Not allowed to accept this request")
    if result == "not_pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    return FriendRequestActionResponse(id=request_id, status="accepted")


@app.post("/friends/requests/{request_id}/decline", response_model=FriendRequestActionResponse)
def decline_friend_request(
    request_id: int,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    result = db.decline_friend_request(request_id, session["username"])
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Request not found")
    if result == "forbidden":
        raise HTTPException(status_code=403, detail="Not allowed to decline this request")
    if result == "not_pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    return FriendRequestActionResponse(id=request_id, status="declined")


@app.post("/friends/requests/{request_id}/cancel", response_model=FriendRequestActionResponse)
def cancel_friend_request(
    request_id: int,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    result = db.cancel_friend_request(request_id, session["username"])
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Request not found")
    if result == "forbidden":
        raise HTTPException(status_code=403, detail="Not allowed to cancel this request")
    if result == "not_pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    return FriendRequestActionResponse(id=request_id, status="cancelled")


@app.get("/friends", response_model=FriendsListResponse)
def list_friends(session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_friends(session["username"])
    return FriendsListResponse(
        friends=[
            FriendEntry(
                username=str(r["peer"]),
                friends_since=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]
    )


@app.post("/friends/remove", response_model=FriendRemoveResponse)
def remove_friend(
    req: FriendTargetRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    target = resolve_friend_target_identifier(req.identifier)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    result = db.remove_friendship(session["username"], target)
    if result == "self":
        raise HTTPException(status_code=400, detail="Cannot remove yourself")
    if result == "not_friends":
        raise HTTPException(status_code=400, detail="Not friends with this user")
    return FriendRemoveResponse(username=target)


@app.post("/friends/block", response_model=FriendBlockResponse)
def block_friend_user(
    req: FriendTargetRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    target = resolve_friend_target_identifier(req.identifier)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    result = db.block_user(session["username"], target)
    if result == "self":
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    return FriendBlockResponse(blocked_username=target)


@app.post("/friends/unblock", response_model=FriendUnblockResponse)
def unblock_friend_user(
    req: FriendTargetRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    target = resolve_friend_target_identifier(req.identifier)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    result = db.unblock_user(session["username"], target)
    if result == "self":
        raise HTTPException(status_code=400, detail="Cannot unblock yourself")
    if result == "not_blocked":
        raise HTTPException(status_code=400, detail="User is not blocked")
    return FriendUnblockResponse(unblocked_username=target)


@app.get("/friends/blocks", response_model=BlockedUsersResponse)
def list_blocked_users(session: Dict[str, str] = Depends(get_current_session)):
    blocked_users = db.list_blocked_users(session["username"])
    return BlockedUsersResponse(blocked_users=blocked_users)


@app.post("/friends/requests/{request_id}/block", response_model=FriendBlockResponse)
def block_friend_request(
    request_id: int,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    result, blocked_name = db.block_from_friend_request(request_id, session["username"])
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Request not found")
    if result == "forbidden":
        raise HTTPException(status_code=403, detail="Not allowed to block for this request")
    if result == "not_pending":
        raise HTTPException(status_code=400, detail="Request is not pending")
    return FriendBlockResponse(blocked_username=blocked_name or "")


@app.post("/sessions/init", response_model=SessionInitResponse)
def init_session_handshake(
    req: SessionInitRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])

    target_username = normalize_username(req.target_username)
    if target_username == session["username"]:
        raise HTTPException(status_code=400, detail="Cannot create session with yourself")
    if not db.get_user(target_username):
        raise HTTPException(status_code=404, detail="Target user not found")
    if db.pair_has_block(session["username"], target_username):
        raise HTTPException(status_code=403, detail="Cannot create session with blocked user")
    if not db.are_friends(session["username"], target_username):
        raise HTTPException(status_code=403, detail="You can only create sessions with friends")

    target_device_id = resolve_target_device_id(target_username, req.target_device_id.strip())
    if not target_device_id:
        raise HTTPException(status_code=404, detail="Target device key not found")

    handshake_id = db.create_session_handshake(
        initiator_user=session["username"],
        initiator_device_id=session["device_id"],
        recipient_user=target_username,
        recipient_device_id=target_device_id,
        initiator_ephemeral_pub=req.initiator_ephemeral_pub,
        initiator_signature=req.initiator_signature,
    )
    return SessionInitResponse(
        handshake_id=handshake_id,
        recipient_username=target_username,
        recipient_device_id=target_device_id,
        status="pending",
    )


@app.get("/sessions/pending", response_model=PendingSessionHandshakeListResponse)
def list_pending_session_handshakes(session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_pending_session_handshakes(session["username"], session["device_id"])
    return PendingSessionHandshakeListResponse(
        handshakes=[
            PendingSessionHandshakeEntry(
                id=int(row["id"]),
                initiator_username=str(row["initiator_user"]),
                initiator_device_id=str(row["initiator_device_id"]),
                recipient_device_id=str(row["recipient_device_id"] or session["device_id"]),
                initiator_ephemeral_pub=str(row["initiator_ephemeral_pub"]),
                initiator_signature=str(row["initiator_signature"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
            )
            for row in rows
        ]
    )


@app.post("/sessions/{handshake_id}/respond", response_model=SessionRespondResponse)
def respond_session_handshake(
    handshake_id: int,
    req: SessionRespondRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])
    result = db.respond_session_handshake(
        handshake_id=handshake_id,
        acting_user=session["username"],
        acting_device_id=session["device_id"],
        responder_ephemeral_pub=req.responder_ephemeral_pub,
        responder_signature=req.responder_signature,
    )
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Handshake not found")
    if result == "forbidden":
        raise HTTPException(status_code=403, detail="Not allowed to respond to this handshake")
    if result == "not_pending":
        raise HTTPException(status_code=400, detail="Handshake is not pending")
    return SessionRespondResponse(handshake_id=handshake_id, status="responded")


@app.get("/sessions/responded", response_model=RespondedSessionHandshakeListResponse)
def list_responded_session_handshakes(session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_responded_session_handshakes_for_initiator(
        initiator_user=session["username"],
        initiator_device_id=session["device_id"],
    )
    return RespondedSessionHandshakeListResponse(
        handshakes=[
            RespondedSessionHandshakeEntry(
                id=int(row["id"]),
                recipient_username=str(row["recipient_user"]),
                recipient_device_id=str(row["recipient_device_id"]),
                initiator_ephemeral_pub=str(row["initiator_ephemeral_pub"]),
                responder_ephemeral_pub=str(row["responder_ephemeral_pub"]),
                responder_signature=str(row["responder_signature"]),
                responded_at=datetime.fromisoformat(str(row["responded_at"])),
            )
            for row in rows
            if row["responder_ephemeral_pub"] and row["responder_signature"] and row["responded_at"]
        ]
    )


@app.post("/messages/send", response_model=SendMessageResponse)
def send_message(
    req: SendMessageRequest,
    request: Request,
    session: Dict[str, str] = Depends(get_current_session),
):
    ip = client_ip(request)
    rate_limiter.check("friend_action", f"{ip}:{session['username']}", *RATE_LIMITS["friend_action"])

    recipient_username = normalize_username(req.recipient_username)
    if recipient_username == session["username"]:
        raise HTTPException(status_code=400, detail="Cannot send message to yourself")
    if not db.get_user(recipient_username):
        raise HTTPException(status_code=404, detail="Recipient user not found")
    if db.pair_has_block(session["username"], recipient_username):
        raise HTTPException(status_code=403, detail="Cannot send message to blocked user")
    if not db.are_friends(session["username"], recipient_username):
        raise HTTPException(status_code=403, detail="Only friends can exchange messages")

    recipient_device_id = req.recipient_device_id.strip() or None
    if recipient_device_id:
        target_device = resolve_target_device_id(recipient_username, recipient_device_id)
        if not target_device:
            raise HTTPException(status_code=404, detail="Recipient device not found")
        recipient_device_id = target_device

    expires_at = None
    if req.expires_in_seconds > 0:
        expires_at = (datetime.utcnow() + timedelta(seconds=req.expires_in_seconds)).isoformat()

    msg_id, created_at = db.create_message(
        sender_user=session["username"],
        sender_device_id=session["device_id"],
        recipient_user=recipient_username,
        recipient_device_id=recipient_device_id,
        ciphertext=req.ciphertext,
        nonce=req.nonce,
        aad=req.aad,
        sender_counter=req.sender_counter,
        expires_at=expires_at,
    )
    return SendMessageResponse(
        message_id=msg_id,
        status="sent",
        sent_at=datetime.fromisoformat(created_at),
    )


@app.get("/messages/poll", response_model=PollMessagesResponse)
def poll_messages(session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_pending_messages_for_recipient(
        recipient_user=session["username"],
        recipient_device_id=session["device_id"],
        limit=100,
    )
    return PollMessagesResponse(
        messages=[
            MessageEnvelope(
                id=int(row["id"]),
                sender_username=str(row["sender_user"]),
                sender_device_id=str(row["sender_device_id"]),
                recipient_username=str(row["recipient_user"]),
                recipient_device_id=str(row["recipient_device_id"] or session["device_id"]),
                ciphertext=str(row["ciphertext"]),
                nonce=str(row["nonce"]),
                aad=str(row["aad"]),
                sender_counter=int(row["sender_counter"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
                expires_at=datetime.fromisoformat(str(row["expires_at"])) if row["expires_at"] else None,
            )
            for row in rows
        ]
    )


@app.post("/messages/{message_id}/ack", response_model=MessageAckResponse)
def ack_message(message_id: int, session: Dict[str, str] = Depends(get_current_session)):
    result = db.ack_message_delivery(message_id, session["username"], session["device_id"])
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Message not found")
    if result == "forbidden":
        raise HTTPException(status_code=403, detail="Not allowed to ack this message")
    return MessageAckResponse(message_id=message_id, status="delivered")


@app.post("/messages/status", response_model=MessageStatusResponse)
def message_status(req: MessageStatusRequest, session: Dict[str, str] = Depends(get_current_session)):
    rows = db.list_message_delivery_statuses_for_sender(session["username"], req.message_ids)
    statuses = []
    for row in rows:
        delivered_at_raw = row["delivered_at"]
        statuses.append(
            MessageStatusEntry(
                message_id=int(row["id"]),
                status="delivered" if delivered_at_raw else "sent",
                delivered_at=datetime.fromisoformat(str(delivered_at_raw)) if delivered_at_raw else None,
            )
        )
    return MessageStatusResponse(statuses=statuses)


@app.post("/keys", response_model=UploadKeyResponse)
def upload_public_key(req: UploadKeyRequest, session: Dict[str, str] = Depends(get_current_session)):
    fingerprint = fingerprint_for_pem(req.public_key_pem)
    updated_at = db.upsert_identity_key(
        username=session["username"],
        device_id=session["device_id"],
        public_key_pem=req.public_key_pem,
        fingerprint=fingerprint,
    )
    return UploadKeyResponse(
        device_id=session["device_id"],
        fingerprint=fingerprint,
        updated_at=updated_at,
    )


@app.get("/keys/{username}", response_model=PublicKeysResponse)
def get_public_keys(username: str, session: Dict[str, str] = Depends(get_current_session)):
    normalized_username = normalize_username(username)
    if db.pair_has_block(session["username"], normalized_username):
        raise HTTPException(status_code=403, detail="You cannot access this user's keys (blocked)")
    rows = db.list_identity_keys(normalized_username)
    keys = [
        PublicKeyEntry(
            device_id=row["device_id"],
            public_key_pem=row["public_key_pem"],
            fingerprint=row["fingerprint"],
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
        for row in rows
    ]
    return PublicKeysResponse(username=normalized_username, keys=keys)


@app.get("/keys/{username}/fingerprint")
def get_public_key_fingerprints(username: str, session: Dict[str, str] = Depends(get_current_session)):
    normalized_username = normalize_username(username)
    if db.pair_has_block(session["username"], normalized_username):
        raise HTTPException(status_code=403, detail="You cannot access this user's keys (blocked)")
    rows = db.list_identity_keys(normalized_username)
    return {
        "username": normalized_username,
        "fingerprints": [
            {
                "device_id": row["device_id"],
                "fingerprint": row["fingerprint"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ],
    }


@app.post("/prekeys/upload", response_model=UploadPrekeysResponse)
def upload_prekeys(req: UploadPrekeysRequest, session: Dict[str, str] = Depends(get_current_session)):
    prekeys = [
        {
            "prekey_id": item.prekey_id,
            "prekey_public": item.prekey_public,
            "prekey_signature": item.prekey_signature,
        }
        for item in req.prekeys
    ]
    uploaded = db.upsert_prekeys(
        username=session["username"],
        device_id=session["device_id"],
        prekeys=prekeys,
    )
    return UploadPrekeysResponse(uploaded=uploaded)


@app.get("/prekeys/{username}/claim", response_model=ClaimPrekeyResponse)
def claim_prekey_bundle(
    username: str,
    device_id: str = "",
    session: Dict[str, str] = Depends(get_current_session),
):
    target_username = normalize_username(username)
    if target_username == session["username"]:
        raise HTTPException(status_code=400, detail="Cannot claim prekey for yourself")
    if not db.get_user(target_username):
        raise HTTPException(status_code=404, detail="Target user not found")
    if db.pair_has_block(session["username"], target_username):
        raise HTTPException(status_code=403, detail="Cannot claim prekey for blocked user")
    if not db.are_friends(session["username"], target_username):
        raise HTTPException(status_code=403, detail="Only friends can claim prekeys")

    preferred_device_id = device_id.strip() if device_id else ""
    if not preferred_device_id:
        keys = db.list_identity_keys(target_username)
        if keys:
            preferred_device_id = str(keys[0]["device_id"])
    claimed = db.claim_prekey(target_username, preferred_device_id or None)
    if not claimed and preferred_device_id:
        claimed = db.claim_prekey(target_username, None)
    if not claimed:
        raise HTTPException(status_code=404, detail="No available prekey for target user")

    keys = db.list_identity_keys(target_username)
    identity_key_pem = ""
    target_device = str(claimed["device_id"])
    for key_row in keys:
        if str(key_row["device_id"]) == target_device:
            identity_key_pem = str(key_row["public_key_pem"])
            break
    if not identity_key_pem:
        raise HTTPException(status_code=404, detail="Target identity key not found")

    return ClaimPrekeyResponse(
        username=target_username,
        device_id=target_device,
        identity_key_pem=identity_key_pem,
        prekey_id=str(claimed["prekey_id"]),
        prekey_public=str(claimed["prekey_public"]),
        prekey_signature=str(claimed["prekey_signature"]),
    )


if __name__ == "__main__":
    cert_file = Path(os.environ.get("IM_TLS_CERT_FILE", str(Path(__file__).resolve().parent / "certs" / "localhost.crt")))
    key_file = Path(os.environ.get("IM_TLS_KEY_FILE", str(Path(__file__).resolve().parent / "certs" / "localhost.key")))
    host = os.environ.get("IM_SERVER_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.environ.get("IM_SERVER_PORT", "8443"))

    if not cert_file.exists() or not key_file.exists():
        raise RuntimeError(
            "TLS certificate/key not found. Set IM_TLS_CERT_FILE and IM_TLS_KEY_FILE, "
            "or place localhost.crt and localhost.key under server/certs/."
        )

    try:
        uvicorn.run(
            app,
            host=host,
            port=port,
            ssl_certfile=str(cert_file),
            ssl_keyfile=str(key_file),
        )
    except KeyboardInterrupt:
        pass
    finally:
        print("Server Terminated")