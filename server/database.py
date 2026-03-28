from datetime import datetime
import secrets
import sqlite3
import string
import threading
from typing import List, Optional, Tuple

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
            self._ensure_friend_tables_schema(cur)
            self._ensure_contact_code_column(cur)
            self.conn.commit()

    def _ensure_friend_tables_schema(self, cur: sqlite3.Cursor) -> None:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='friend_requests'")
        if cur.fetchone():
            cur.execute("PRAGMA table_info(friend_requests)")
            cols = {row[1] for row in cur.fetchall()}
            needed_fr = {"from_user", "to_user", "status", "created_at", "updated_at"}
            if not needed_fr.issubset(cols):
                cur.execute("DROP TABLE IF EXISTS friend_requests")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'accepted', 'declined')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(from_user, to_user),
                FOREIGN KEY(from_user) REFERENCES users(username),
                FOREIGN KEY(to_user) REFERENCES users(username)
            )
            """
        )

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='friendships'")
        if cur.fetchone():
            cur.execute("PRAGMA table_info(friendships)")
            cols = {row[1] for row in cur.fetchall()}
            needed_fs = {"user_a", "user_b", "created_at"}
            if not needed_fs.issubset(cols):
                cur.execute("DROP TABLE IF EXISTS friendships")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS friendships (
                user_a TEXT NOT NULL,
                user_b TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(user_a, user_b),
                CHECK(user_a < user_b),
                FOREIGN KEY(user_a) REFERENCES users(username),
                FOREIGN KEY(user_b) REFERENCES users(username)
            )
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_user, status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_friend_requests_from ON friend_requests(from_user, status)")

    def _ensure_contact_code_column(self, cur: sqlite3.Cursor) -> None:
        cur.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cur.fetchall()}
        if "contact_code" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN contact_code TEXT")

        cur.execute(
            "SELECT username FROM users WHERE contact_code IS NULL OR contact_code = ''",
        )
        for (uname,) in cur.fetchall():
            code = self._new_unique_contact_code_locked(cur)
            cur.execute("UPDATE users SET contact_code = ? WHERE username = ?", (code, uname))

        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_contact_code
            ON users(contact_code) WHERE contact_code IS NOT NULL AND contact_code != ''
            """
        )

    def _new_unique_contact_code_locked(self, cur: sqlite3.Cursor) -> str:
        alphabet = string.ascii_uppercase + string.digits
        for _ in range(64):
            code = "".join(secrets.choice(alphabet) for _ in range(8))
            row = cur.execute(
                "SELECT 1 FROM users WHERE contact_code = ?",
                (code,),
            ).fetchone()
            if not row:
                return code
        raise RuntimeError("Could not allocate unique contact code")

    def create_user(self, username: str, password_hash: str, otp_secret: str) -> str:
        created = datetime.utcnow().isoformat()
        with self.lock:
            cur = self.conn.cursor()
            code = self._new_unique_contact_code_locked(cur)
            cur.execute(
                """
                INSERT INTO users(username, password_hash, otp_secret, created_at, contact_code)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, password_hash, otp_secret, created, code),
            )
            self.conn.commit()
        return code

    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        with self.lock:
            row = self.conn.execute(
                "SELECT username, password_hash, otp_secret, contact_code FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return row

    def get_user_by_contact_code(self, contact_code: str) -> Optional[sqlite3.Row]:
        normalized = contact_code.strip().upper()
        if not normalized:
            return None
        with self.lock:
            return self.conn.execute(
                "SELECT username, password_hash, otp_secret, contact_code FROM users WHERE contact_code = ?",
                (normalized,),
            ).fetchone()

    def _friendship_pair(self, u1: str, u2: str) -> Tuple[str, str]:
        if u1 == u2:
            return u1, u2
        return (u1, u2) if u1 < u2 else (u2, u1)

    def _are_friends_unlocked(self, u1: str, u2: str) -> bool:
        if u1 == u2:
            return False
        a, b = self._friendship_pair(u1, u2)
        row = self.conn.execute(
            "SELECT 1 FROM friendships WHERE user_a = ? AND user_b = ?",
            (a, b),
        ).fetchone()
        return row is not None

    def are_friends(self, u1: str, u2: str) -> bool:
        with self.lock:
            return self._are_friends_unlocked(u1, u2)

    def _get_request_row(self, from_user: str, to_user: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT id, from_user, to_user, status, created_at, updated_at FROM friend_requests WHERE from_user = ? AND to_user = ?",
            (from_user, to_user),
        ).fetchone()

    def create_or_refresh_friend_request(self, from_user: str, to_user: str) -> Tuple[int, str, str]:
        """Returns (request_id, status, detail_message_for_error). detail empty if ok."""
        if from_user == to_user:
            return -1, "", "cannot_add_self"

        now = datetime.utcnow().isoformat()

        with self.lock:
            if self._are_friends_unlocked(from_user, to_user):
                return -1, "", "already_friends"

            reverse = self._get_request_row(to_user, from_user)
            if reverse and reverse["status"] == "pending":
                return -1, "", "incoming_pending_exists"

            row = self._get_request_row(from_user, to_user)

            if row and row["status"] == "pending":
                return -1, "", "duplicate_pending"

            if row and row["status"] == "accepted":
                return -1, "", "already_friends"

            if row and row["status"] == "declined":
                self.conn.execute(
                    """
                    UPDATE friend_requests
                    SET status = 'pending', updated_at = ?
                    WHERE id = ?
                    """,
                    (now, row["id"]),
                )
                self.conn.commit()
                return int(row["id"]), "pending", ""

            self.conn.execute(
                """
                INSERT INTO friend_requests(from_user, to_user, status, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?)
                """,
                (from_user, to_user, now, now),
            )
            rid = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            self.conn.commit()
            return rid, "pending", ""

    def list_incoming_friend_requests(self, username: str) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT id, from_user, created_at
                FROM friend_requests
                WHERE to_user = ? AND status = 'pending'
                ORDER BY created_at DESC
                """,
                (username,),
            ).fetchall()

    def list_outgoing_friend_requests(self, username: str) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT id, to_user, created_at
                FROM friend_requests
                WHERE from_user = ? AND status = 'pending'
                ORDER BY created_at DESC
                """,
                (username,),
            ).fetchall()

    def get_friend_request_by_id(self, request_id: int) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT id, from_user, to_user, status, created_at, updated_at
                FROM friend_requests WHERE id = ?
                """,
                (request_id,),
            ).fetchone()

    def accept_friend_request(self, request_id: int, acting_user: str) -> str:
        now = datetime.utcnow().isoformat()
        with self.lock:
            row = self.conn.execute(
                "SELECT id, from_user, to_user, status FROM friend_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return "not_found"
            if row["to_user"] != acting_user:
                return "forbidden"
            if row["status"] != "pending":
                return "not_pending"

            a, b = self._friendship_pair(row["from_user"], row["to_user"])
            self.conn.execute(
                """
                INSERT OR IGNORE INTO friendships(user_a, user_b, created_at)
                VALUES (?, ?, ?)
                """,
                (a, b, now),
            )
            self.conn.execute(
                """
                UPDATE friend_requests SET status = 'accepted', updated_at = ? WHERE id = ?
                """,
                (now, request_id),
            )
            self.conn.commit()
            return "ok"

    def decline_friend_request(self, request_id: int, acting_user: str) -> str:
        now = datetime.utcnow().isoformat()
        with self.lock:
            row = self.conn.execute(
                "SELECT id, to_user, status FROM friend_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return "not_found"
            if row["to_user"] != acting_user:
                return "forbidden"
            if row["status"] != "pending":
                return "not_pending"

            self.conn.execute(
                """
                UPDATE friend_requests SET status = 'declined', updated_at = ? WHERE id = ?
                """,
                (now, request_id),
            )
            self.conn.commit()
            return "ok"

    def list_friends(self, username: str) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT
                    CASE WHEN user_a = ? THEN user_b ELSE user_a END AS peer,
                    created_at
                FROM friendships
                WHERE user_a = ? OR user_b = ?
                ORDER BY peer
                """,
                (username, username, username),
            ).fetchall()

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
