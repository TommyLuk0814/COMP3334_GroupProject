from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "secure_im.db"
SESSION_TTL_HOURS = 1

RATE_LIMITS = {
    "register": (5, 60),
    "login_password": (10, 60),
    "login_otp": (10, 60),
    "friend_action": (30, 60),
}
