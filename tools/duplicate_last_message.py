import argparse
import sqlite3
from pathlib import Path
from typing import Optional


def resolve_db_path(raw_path: str) -> Path:
    return Path(__file__).resolve().parent.parent / "server" / "secure_im.db"


def fetch_message(conn: sqlite3.Connection, message_id: Optional[int]):
    conn.row_factory = sqlite3.Row
    if message_id is None:
        row = conn.execute(
            """
            SELECT sender_user, sender_device_id, recipient_user, recipient_device_id,
                   ciphertext, nonce, aad, sender_counter, expires_at
            FROM messages
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT sender_user, sender_device_id, recipient_user, recipient_device_id,
                   ciphertext, nonce, aad, sender_counter, expires_at
            FROM messages
            WHERE id = ?
            """,
            (message_id,),
        ).fetchone()
    return row


def duplicate_message(conn: sqlite3.Connection, row: sqlite3.Row) -> int:
    cursor = conn.execute(
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, NULL)
        """,
        (
            row["sender_user"],
            row["sender_device_id"],
            row["recipient_user"],
            row["recipient_device_id"],
            row["ciphertext"],
            row["nonce"],
            row["aad"],
            row["sender_counter"],
            row["expires_at"],
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def main():
    parser = argparse.ArgumentParser(description="Duplicate a message row for replay testing.")
    parser.add_argument("--message-id", type=int, default=None, help="Message id to duplicate (default: latest)")
    args = parser.parse_args()

    db_path = resolve_db_path("")
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        row = fetch_message(conn, args.message_id)
        if row is None:
            raise SystemExit("No message found to duplicate.")

        new_id = duplicate_message(conn, row)
        print(f"Duplicated message as new row id: {new_id}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()