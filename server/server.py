from datetime import datetime, timedelta
from typing import Dict
import secrets

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import pyotp
import uvicorn

from config import RATE_LIMITS, SESSION_TTL_HOURS
from database import db
from rate_limiter import RateLimiter
from schemas import (
    LoginOTPRequest,
    LoginOTPResponse,
    LoginPasswordRequest,
    LoginPasswordResponse,
    LogoutResponse,
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
    db.create_user(normalized_username, hash_password(req.password), otp_secret)
    return RegisterResponse(otp_secret=otp_secret)


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


@app.get("/me")
def me(session: Dict[str, str] = Depends(get_current_session)):
    return {
        "username": session["username"],
        "device_id": session["device_id"],
    }


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