from datetime import datetime
import secrets
import sqlite3
import string
import threading
from typing import Dict, List, Optional, Tuple

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
            self._ensure_blocks_table(cur)
            self._ensure_contact_code_column(cur)
            self._ensure_session_handshakes_table(cur)
            self._ensure_messages_table(cur)
            self._ensure_prekeys_table(cur)
            self.conn.commit()

    def _ensure_prekeys_table(self, cur: sqlite3.Cursor) -> None:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                device_id TEXT NOT NULL,
                prekey_id TEXT NOT NULL,
                prekey_public TEXT NOT NULL,
                prekey_signature TEXT NOT NULL,
                created_at TEXT NOT NULL,
                consumed_at TEXT,
                UNIQUE(username, device_id, prekey_id),
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_prekeys_available ON prekeys(username, device_id, consumed_at, created_at)"
        )

    def _ensure_messages_table(self, cur: sqlite3.Cursor) -> None:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_user TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                recipient_user TEXT NOT NULL,
                recipient_device_id TEXT,
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                aad TEXT NOT NULL,
                sender_counter INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                delivered_at TEXT,
                FOREIGN KEY(sender_user) REFERENCES users(username),
                FOREIGN KEY(recipient_user) REFERENCES users(username)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient_pending ON messages(recipient_user, delivered_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at)")

    def _ensure_session_handshakes_table(self, cur: sqlite3.Cursor) -> None:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS session_handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                initiator_user TEXT NOT NULL,
                initiator_device_id TEXT NOT NULL,
                recipient_user TEXT NOT NULL,
                recipient_device_id TEXT,
                initiator_ephemeral_pub TEXT NOT NULL,
                initiator_signature TEXT NOT NULL,
                responder_ephemeral_pub TEXT,
                responder_signature TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'responded')),
                created_at TEXT NOT NULL,
                responded_at TEXT,
                FOREIGN KEY(initiator_user) REFERENCES users(username),
                FOREIGN KEY(recipient_user) REFERENCES users(username)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_handshakes_recipient ON session_handshakes(recipient_user, status)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_handshakes_initiator ON session_handshakes(initiator_user, status)"
        )

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

    def _ensure_blocks_table(self, cur: sqlite3.Cursor) -> None:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                blocker TEXT NOT NULL,
                blocked TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (blocker, blocked),
                CHECK (blocker != blocked),
                FOREIGN KEY(blocker) REFERENCES users(username),
                FOREIGN KEY(blocked) REFERENCES users(username)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked)")

    def _pair_has_block_unlocked(self, u1: str, u2: str) -> bool:
        if u1 == u2:
            return False
        row = self.conn.execute(
            """
            SELECT 1 FROM blocks
            WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)
            LIMIT 1
            """,
            (u1, u2, u2, u1),
        ).fetchone()
        return row is not None

    def pair_has_block(self, u1: str, u2: str) -> bool:
        with self.lock:
            return self._pair_has_block_unlocked(u1, u2)

    def _delete_all_friend_requests_between_unlocked(self, a: str, b: str) -> None:
        """Remove request rows in both directions so stale 'accepted' rows cannot block re-adding."""
        self.conn.execute(
            """
            DELETE FROM friend_requests
            WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
            """,
            (a, b, b, a),
        )

    def remove_friendship(self, acting_user: str, peer: str) -> str:
        if acting_user == peer:
            return "self"
        a, b = self._friendship_pair(acting_user, peer)
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM friendships WHERE user_a = ? AND user_b = ?",
                (a, b),
            )
            if cur.rowcount == 0:
                return "not_friends"
            self._delete_all_friend_requests_between_unlocked(acting_user, peer)
            self.conn.commit()
            return "ok"

    def _block_user_unlocked(self, blocker: str, blocked: str, now: str) -> str:
        exists = self.conn.execute(
            "SELECT 1 FROM blocks WHERE blocker = ? AND blocked = ?",
            (blocker, blocked),
        ).fetchone()
        if exists:
            return "ok"
        a, b = self._friendship_pair(blocker, blocked)
        self.conn.execute(
            "DELETE FROM friendships WHERE user_a = ? AND user_b = ?",
            (a, b),
        )
        self._delete_all_friend_requests_between_unlocked(blocker, blocked)
        self.conn.execute(
            """
            INSERT INTO blocks(blocker, blocked, created_at)
            VALUES (?, ?, ?)
            """,
            (blocker, blocked, now),
        )
        # Drop queued ciphertext in both directions once either side blocks the other.
        self.conn.execute(
            """
            DELETE FROM messages
            WHERE delivered_at IS NULL
              AND (
                    (sender_user = ? AND recipient_user = ?)
                 OR (sender_user = ? AND recipient_user = ?)
              )
            """,
            (blocker, blocked, blocked, blocker),
        )
        self.conn.commit()
        return "ok"

    def block_user(self, blocker: str, blocked: str) -> str:
        if blocker == blocked:
            return "self"
        now = datetime.utcnow().isoformat()
        with self.lock:
            return self._block_user_unlocked(blocker, blocked, now)

    def unblock_user(self, blocker: str, blocked: str) -> str:
        if blocker == blocked:
            return "self"
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM blocks WHERE blocker = ? AND blocked = ?",
                (blocker, blocked),
            )
            self.conn.commit()
            if cur.rowcount == 0:
                return "not_blocked"
            return "ok"

    def list_blocked_users(self, blocker: str) -> List[str]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT blocked FROM blocks WHERE blocker = ? ORDER BY blocked",
                (blocker,),
            ).fetchall()
            return [str(r["blocked"]) for r in rows]

    def block_from_friend_request(self, request_id: int, acting_user: str) -> Tuple[str, Optional[str]]:
        now = datetime.utcnow().isoformat()
        with self.lock:
            row = self.conn.execute(
                "SELECT id, from_user, to_user, status FROM friend_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return "not_found", None
            if row["to_user"] != acting_user:
                return "forbidden", None
            if row["status"] != "pending":
                return "not_pending", None
            from_user = str(row["from_user"])
            self._block_user_unlocked(acting_user, from_user, now)
            return "ok", from_user

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
            if self._pair_has_block_unlocked(from_user, to_user):
                return -1, "", "blocked"

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
                SELECT fr.id, fr.from_user, fr.created_at
                FROM friend_requests fr
                WHERE fr.to_user = ? AND fr.status = 'pending'
                  AND NOT EXISTS (
                    SELECT 1 FROM blocks b
                    WHERE (b.blocker = ? AND b.blocked = fr.from_user)
                       OR (b.blocker = fr.from_user AND b.blocked = ?)
                  )
                ORDER BY fr.created_at DESC
                """,
                (username, username, username),
            ).fetchall()

    def list_outgoing_friend_requests(self, username: str) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT fr.id, fr.to_user, fr.created_at
                FROM friend_requests fr
                WHERE fr.from_user = ? AND fr.status = 'pending'
                  AND NOT EXISTS (
                    SELECT 1 FROM blocks b
                    WHERE (b.blocker = ? AND b.blocked = fr.to_user)
                       OR (b.blocker = fr.to_user AND b.blocked = ?)
                  )
                ORDER BY fr.created_at DESC
                """,
                (username, username, username),
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

    def cancel_friend_request(self, request_id: int, acting_user: str) -> str:
        with self.lock:
            row = self.conn.execute(
                "SELECT id, from_user, status FROM friend_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return "not_found"
            if row["from_user"] != acting_user:
                return "forbidden"
            if row["status"] != "pending":
                return "not_pending"
            self.conn.execute("DELETE FROM friend_requests WHERE id = ?", (request_id,))
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

    def create_session_handshake(
        self,
        initiator_user: str,
        initiator_device_id: str,
        recipient_user: str,
        recipient_device_id: Optional[str],
        initiator_ephemeral_pub: str,
        initiator_signature: str,
    ) -> int:
        now = datetime.utcnow().isoformat()
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO session_handshakes(
                    initiator_user,
                    initiator_device_id,
                    recipient_user,
                    recipient_device_id,
                    initiator_ephemeral_pub,
                    initiator_signature,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (
                    initiator_user,
                    initiator_device_id,
                    recipient_user,
                    recipient_device_id,
                    initiator_ephemeral_pub,
                    initiator_signature,
                    now,
                ),
            )
            hid = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            self.conn.commit()
            return hid

    def list_pending_session_handshakes(self, recipient_user: str, recipient_device_id: str) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT
                    id,
                    initiator_user,
                    initiator_device_id,
                    recipient_user,
                    recipient_device_id,
                    initiator_ephemeral_pub,
                    initiator_signature,
                    created_at
                FROM session_handshakes
                WHERE recipient_user = ?
                  AND status = 'pending'
                  AND (recipient_device_id IS NULL OR recipient_device_id = ?)
                ORDER BY created_at ASC
                """,
                (recipient_user, recipient_device_id),
            ).fetchall()

    def respond_session_handshake(
        self,
        handshake_id: int,
        acting_user: str,
        acting_device_id: str,
        responder_ephemeral_pub: str,
        responder_signature: str,
    ) -> str:
        now = datetime.utcnow().isoformat()
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, recipient_user, recipient_device_id, status
                FROM session_handshakes
                WHERE id = ?
                """,
                (handshake_id,),
            ).fetchone()
            if not row:
                return "not_found"
            if row["recipient_user"] != acting_user:
                return "forbidden"
            if row["recipient_device_id"] and row["recipient_device_id"] != acting_device_id:
                return "forbidden"
            if row["status"] != "pending":
                return "not_pending"

            self.conn.execute(
                """
                UPDATE session_handshakes
                SET responder_ephemeral_pub = ?,
                    responder_signature = ?,
                    status = 'responded',
                    responded_at = ?,
                    recipient_device_id = COALESCE(recipient_device_id, ?)
                WHERE id = ?
                """,
                (responder_ephemeral_pub, responder_signature, now, acting_device_id, handshake_id),
            )
            self.conn.commit()
            return "ok"

    def list_responded_session_handshakes_for_initiator(
        self,
        initiator_user: str,
        initiator_device_id: str,
    ) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                """
                SELECT
                    id,
                    initiator_user,
                    initiator_device_id,
                    recipient_user,
                    recipient_device_id,
                    initiator_ephemeral_pub,
                    initiator_signature,
                    responder_ephemeral_pub,
                    responder_signature,
                    created_at,
                    responded_at
                FROM session_handshakes
                WHERE initiator_user = ?
                  AND initiator_device_id = ?
                  AND status = 'responded'
                ORDER BY responded_at DESC
                """,
                (initiator_user, initiator_device_id),
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

    def cleanup_expired_messages(self) -> None:
        with self.lock:
            self._cleanup_expired_messages_locked(datetime.utcnow().isoformat())
            self.conn.commit()

    def _cleanup_expired_messages_locked(self, now: str) -> None:
        self.conn.execute(
            "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )

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

    def upsert_prekeys(self, username: str, device_id: str, prekeys: List[Dict[str, str]]) -> int:
        if not prekeys:
            return 0
        now = datetime.utcnow().isoformat()
        uploaded = 0
        with self.lock:
            for entry in prekeys:
                prekey_id = str(entry.get("prekey_id", "")).strip()
                prekey_public = str(entry.get("prekey_public", "")).strip()
                prekey_signature = str(entry.get("prekey_signature", "")).strip()
                if not prekey_id or not prekey_public or not prekey_signature:
                    continue
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO prekeys(
                        username,
                        device_id,
                        prekey_id,
                        prekey_public,
                        prekey_signature,
                        created_at,
                        consumed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (username, device_id, prekey_id, prekey_public, prekey_signature, now),
                )
                if self.conn.execute("SELECT changes()").fetchone()[0] > 0:
                    uploaded += 1
            self.conn.commit()
        return uploaded

    def claim_prekey(self, username: str, preferred_device_id: Optional[str] = None) -> Optional[sqlite3.Row]:
        now = datetime.utcnow().isoformat()
        with self.lock:
            if preferred_device_id:
                row = self.conn.execute(
                    """
                    SELECT id, username, device_id, prekey_id, prekey_public, prekey_signature
                    FROM prekeys
                    WHERE username = ?
                      AND device_id = ?
                      AND consumed_at IS NULL
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (username, preferred_device_id),
                ).fetchone()
            else:
                row = self.conn.execute(
                    """
                    SELECT id, username, device_id, prekey_id, prekey_public, prekey_signature
                    FROM prekeys
                    WHERE username = ?
                      AND consumed_at IS NULL
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (username,),
                ).fetchone()
            if not row:
                return None
            self.conn.execute(
                "UPDATE prekeys SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
                (now, int(row["id"])),
            )
            if self.conn.execute("SELECT changes()").fetchone()[0] == 0:
                self.conn.commit()
                return None
            self.conn.commit()
            return row

    def create_message(
        self,
        sender_user: str,
        sender_device_id: str,
        recipient_user: str,
        recipient_device_id: Optional[str],
        ciphertext: str,
        nonce: str,
        aad: str,
        sender_counter: int,
        expires_at: Optional[str],
    ) -> Tuple[int, str]:
        created_at = datetime.utcnow().isoformat()
        with self.lock:
            self._cleanup_expired_messages_locked(created_at)
            self.conn.execute(
                """
                INSERT INTO messages(
                    sender_user,
                    sender_device_id,
                    recipient_user,
                    recipient_device_id,
                    ciphertext,
                    nonce,
                    aad,
                    sender_counter,
                    created_at,
                    expires_at,
                    delivered_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    sender_user,
                    sender_device_id,
                    recipient_user,
                    recipient_device_id,
                    ciphertext,
                    nonce,
                    aad,
                    sender_counter,
                    created_at,
                    expires_at,
                ),
            )
            msg_id = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            self.conn.commit()
            return msg_id, created_at

    def list_pending_messages_for_recipient(
        self,
        recipient_user: str,
        recipient_device_id: str,
        limit: int = 100,
    ) -> List[sqlite3.Row]:
        now = datetime.utcnow().isoformat()
        with self.lock:
            self._cleanup_expired_messages_locked(now)
            return self.conn.execute(
                """
                SELECT
                    id,
                    sender_user,
                    sender_device_id,
                    recipient_user,
                    recipient_device_id,
                    ciphertext,
                    nonce,
                    aad,
                    sender_counter,
                    created_at,
                    expires_at
                FROM messages
                WHERE recipient_user = ?
                  AND delivered_at IS NULL
                  AND (recipient_device_id IS NULL OR recipient_device_id = ?)
                  AND (expires_at IS NULL OR expires_at > ?)
                                    AND NOT EXISTS (
                                                SELECT 1
                                                FROM blocks b
                                                WHERE (b.blocker = messages.sender_user AND b.blocked = messages.recipient_user)
                                                     OR (b.blocker = messages.recipient_user AND b.blocked = messages.sender_user)
                                    )
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (recipient_user, recipient_device_id, now, limit),
            ).fetchall()

    def ack_message_delivery(self, message_id: int, acting_user: str, acting_device_id: str) -> str:
        now = datetime.utcnow().isoformat()
        with self.lock:
            self._cleanup_expired_messages_locked(now)
            row = self.conn.execute(
                """
                SELECT id, recipient_user, recipient_device_id, delivered_at
                FROM messages
                WHERE id = ?
                """,
                (message_id,),
            ).fetchone()
            if not row:
                return "not_found"
            if row["recipient_user"] != acting_user:
                return "forbidden"
            if row["recipient_device_id"] and row["recipient_device_id"] != acting_device_id:
                return "forbidden"
            if row["delivered_at"]:
                return "already_acked"

            self.conn.execute(
                "UPDATE messages SET delivered_at = ? WHERE id = ?",
                (now, message_id),
            )
            self.conn.commit()
            return "ok"

    def list_message_delivery_statuses_for_sender(self, sender_user: str, message_ids: List[int]) -> List[sqlite3.Row]:
        if not message_ids:
            return []
        normalized_ids = []
        seen = set()
        for message_id in message_ids:
            try:
                number = int(message_id)
            except Exception:
                continue
            if number <= 0 or number in seen:
                continue
            seen.add(number)
            normalized_ids.append(number)
        if not normalized_ids:
            return []

        placeholders = ",".join(["?"] * len(normalized_ids))
        params = [sender_user] + normalized_ids
        with self.lock:
            query = (
                "SELECT id, delivered_at "
                "FROM messages "
                "WHERE sender_user = ? "
                f"AND id IN ({placeholders})"
            )
            return self.conn.execute(query, params).fetchall()


db = DB(DB_PATH)
