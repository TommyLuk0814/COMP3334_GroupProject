from datetime import datetime
import hashlib
import re
from typing import Dict, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from database import db

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
token_auth_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_username(username: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9]+", username):
        raise HTTPException(
            status_code=400,
            detail="Username can only contain letters and numbers",
        )


def validate_password_policy(password: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9]+", password):
        raise HTTPException(
            status_code=400,
            detail="Password can only contain letters and numbers",
        )


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def fingerprint_for_pem(public_key_pem: str) -> str:
    normalized = public_key_pem.strip().encode("utf-8")
    digest = hashlib.sha256(normalized).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def get_current_session(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(token_auth_scheme),
) -> Dict[str, str]:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db.cleanup_expired_sessions()
    token = creds.credentials
    session = db.get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session["revoked"]:
        raise HTTPException(status_code=401, detail="Token revoked")

    if datetime.fromisoformat(session["expires_at"]) < datetime.utcnow():
        db.revoke_token(token)
        raise HTTPException(status_code=401, detail="Token expired")

    return {
        "token": token,
        "username": session["username"],
        "device_id": session["device_id"],
    }
