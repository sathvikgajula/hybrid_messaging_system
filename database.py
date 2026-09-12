# database.py
import sqlite3
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.environ.get("SEALED_DB") or os.path.join(BASE_DIR, "messenger.db")


def configure(db_path):
    global DB_NAME
    DB_NAME = db_path
    init_db()


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY,
                      public_keys TEXT NOT NULL,
                      identity_sig TEXT NOT NULL DEFAULT '')''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      recipient TEXT NOT NULL,
                      sender TEXT NOT NULL,
                      encrypted_data TEXT NOT NULL)''')
        try:
            c.execute("ALTER TABLE users ADD COLUMN identity_sig TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def register_user_db(username, pub_keys_dict, identity_sig):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute(
                "INSERT INTO users (username, public_keys, identity_sig) VALUES (?, ?, ?)",
                (username, json.dumps(pub_keys_dict), identity_sig)
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_bundle(username):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT public_keys, identity_sig FROM users WHERE username=?",
            (username,),
        )
        result = c.fetchone()
    if not result:
        return None
    return {
        "username": username,
        "public_keys": json.loads(result[0]),
        "identity_sig": result[1],
    }


def get_public_keys(username):
    bundle = get_user_bundle(username)
    return bundle["public_keys"] if bundle else None


def store_message(sender, recipient, encrypted_data):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT INTO messages (sender, recipient, encrypted_data) VALUES (?, ?, ?)",
            (sender, recipient, json.dumps(encrypted_data))
        )


def fetch_messages(recipient, consume=False):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT sender, encrypted_data FROM messages WHERE recipient=?", (recipient,))
        rows = c.fetchall()
        if consume:
            c.execute("DELETE FROM messages WHERE recipient=?", (recipient,))
            conn.commit()
    return [{"from": r[0], "payload": json.loads(r[1])} for r in rows]


def inbox_usage(recipient):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(encrypted_data)), 0) FROM messages WHERE recipient=?",
            (recipient,),
        )
        count, nbytes = c.fetchone()
    return int(count or 0), int(nbytes or 0)


init_db()
