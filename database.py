# database.py
import sqlite3
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "messenger.db")
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Users table: Stores username and their Public Keys (JSON blob)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, public_keys TEXT)''')
    # Messages table: Stores encrypted blobs waiting for delivery
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  recipient TEXT, 
                  sender TEXT, 
                  encrypted_data TEXT)''')
    conn.commit()
    conn.close()

def register_user_db(username, pub_keys_dict):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO users VALUES (?, ?)", (username, json.dumps(pub_keys_dict)))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def get_public_keys(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT public_keys FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    return json.loads(result[0]) if result else None

def store_message(sender, recipient, encrypted_data):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Store the entire JSON blob of ciphertext + signature + scheme info
    c.execute("INSERT INTO messages (sender, recipient, encrypted_data) VALUES (?, ?, ?)",
              (sender, recipient, json.dumps(encrypted_data)))
    conn.commit()
    conn.close()

def fetch_messages(recipient):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT sender, encrypted_data FROM messages WHERE recipient=?", (recipient,))
    rows = c.fetchall()
    conn.close()
    # Return list of dicts
    return [{"from": r[0], "payload": json.loads(r[1])} for r in rows]

# Initialize on import
init_db()