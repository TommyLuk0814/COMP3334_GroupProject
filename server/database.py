from datetime import datetime
import sqlite3
import threading
from typing import List, Optional

from config import DB_PATH


class DB:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._init_tables()

    def _init_tables(self) -> None:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    otp_secret TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(username) REFERENCES users(username)
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS identity_keys (
                    username TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(username, device_id),
                    FOREIGN KEY(username) REFERENCES users(username)
                )
                """
            )
            self.conn.commit()

    def create_user(self, username: str, password_hash: str, otp_secret: str) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO users(username, password_hash, otp_secret, created_at) VALUES (?, ?, ?, ?)",
                (username, password_hash, otp_secret, datetime.utcnow().isoformat()),
            )
            self.conn.commit()

    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        with self.lock:
            row = self.conn.execute(
                "SELECT username, password_hash, otp_secret FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return row

    def upsert_session(self, token: str, username: str, device_id: str, expires_at: datetime) -> None:
        now = datetime.utcnow().isoformat()
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO sessions(token, username, device_id, expires_at, created_at, revoked)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (token, username, device_id, expires_at.isoformat(), now),
            )
            self.conn.commit()

    def get_session(self, token: str) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                "SELECT token, username, device_id, expires_at, revoked FROM sessions WHERE token = ?",
                (token,),
            ).fetchone()

    def revoke_user_sessions(self, username: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE sessions SET revoked = 1 WHERE username = ?", (username,))
            self.conn.commit()

    def revoke_token(self, token: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token,))
            self.conn.commit()

    def cleanup_expired_sessions(self) -> None:
        with self.lock:
            self.conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (datetime.utcnow().isoformat(),),
            )
            self.conn.commit()

    def upsert_identity_key(
        self,
        username: str,
        device_id: str,
        public_key_pem: str,
        fingerprint: str,
    ) -> datetime:
        updated_at = datetime.utcnow()
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO identity_keys(username, device_id, public_key_pem, fingerprint, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(username, device_id)
                DO UPDATE SET public_key_pem = excluded.public_key_pem,
                              fingerprint = excluded.fingerprint,
                              updated_at = excluded.updated_at
                """,
                (username, device_id, public_key_pem, fingerprint, updated_at.isoformat()),
            )
            self.conn.commit()
        return updated_at

    def list_identity_keys(self, username: str) -> List[sqlite3.Row]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT device_id, public_key_pem, fingerprint, updated_at
                FROM identity_keys
                WHERE username = ?
                ORDER BY updated_at DESC
                """,
                (username,),
            ).fetchall()
            return rows


db = DB(DB_PATH)
