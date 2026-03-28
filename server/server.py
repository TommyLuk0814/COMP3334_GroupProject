from datetime import datetime, timedelta
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
    FriendEntry,
    FriendRequestActionResponse,
    FriendRequestEntry,
    FriendRequestListResponse,
    FriendRequestSendRequest,
    FriendRequestSendResponse,
    FriendsListResponse,
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
    UploadKeyRequest,
    UploadKeyResponse,
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
    _ = session
    normalized_username = normalize_username(username)
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
    _ = session
    normalized_username = normalize_username(username)
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


if __name__ == "__main__":
    try:
        uvicorn.run(app, host="127.0.0.1", port=8000)
    except KeyboardInterrupt:
        pass
    finally:
        print("Server Terminated")