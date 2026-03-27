from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, constr
from passlib.context import CryptContext
import pyotp
import secrets


app = FastAPI(title="Secure IM Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
token_auth_scheme = HTTPBearer(auto_error=False)


class UserInDB(BaseModel):
    username: str
    password_hash: str
    otp_secret: str


class RegisterRequest(BaseModel):
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=6, max_length=128)


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


class LoginOTPResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class LogoutResponse(BaseModel):
    detail: str


users_db: dict[str, UserInDB] = {}
sessions_db: dict[str, dict] = {}


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


@app.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest):
    if req.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    otp_secret = pyotp.random_base32()
    users_db[req.username] = UserInDB(
        username=req.username,
        password_hash=hash_password(req.password),
        otp_secret=otp_secret,
    )
    return RegisterResponse(otp_secret=otp_secret)


@app.post("/login/password", response_model=LoginPasswordResponse)
def login_password(req: LoginPasswordRequest):
    user = users_db.get(req.username)
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return LoginPasswordResponse(otp_required=True)


@app.post("/login/otp", response_model=LoginOTPResponse)
def login_otp(req: LoginOTPRequest):
    user = users_db.get(req.username)
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    totp = pyotp.TOTP(user.otp_secret)
    if not totp.verify(req.otp, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid OTP")
    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    sessions_db[token] = {
        "username": user.username,
        "expires_at": expires_at,
    }
    return LoginOTPResponse(access_token=token, expires_at=expires_at)


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(token_auth_scheme),
) -> str:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = creds.credentials
    session = sessions_db.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session["expires_at"] < datetime.utcnow():
        sessions_db.pop(token, None)
        raise HTTPException(status_code=401, detail="Token expired")
    return session["username"]


@app.post("/logout", response_model=LogoutResponse)
def logout(username: str = Depends(get_current_user)):
    tokens_to_delete = [t for t, s in sessions_db.items() if s["username"] == username]
    for t in tokens_to_delete:
        sessions_db.pop(t, None)
    return LogoutResponse(detail="Logged out")


@app.get("/me")
def me(username: str = Depends(get_current_user)):
    return {"username": username}

