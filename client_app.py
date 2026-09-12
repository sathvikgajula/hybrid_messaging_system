# client_app.py
import requests
import os
import sys

import protocol
import keyfile

SERVER_URL = "http://127.0.0.1:8000"

my_identity = None
my_keys = {}
KEY_FILE = "my_private_keys.json"


def _ensure_registered():
    try:
        resp = requests.get(f"{SERVER_URL}/keys/{my_identity}")
        if resp.status_code == 404:
            pubs, sig = protocol.sign_identity_bundle(my_identity, my_keys)
            reg = requests.post(f"{SERVER_URL}/register", json={
                "username": my_identity,
                "public_keys": pubs,
                "identity_sig": sig,
            })
            if reg.status_code == 200:
                print("Re-registered public keys on the server.")
            else:
                print(f"Could not re-register on the server: {reg.text}")
        elif resp.status_code != 200:
            print(f"Warning: server returned {resp.status_code} looking up your keys.")
    except requests.RequestException as e:
        print(f"Warning: server looks offline ({e}). Sending/inbox will fail until it is up.")


def load_or_generate_keys():
    global my_keys, my_identity

    if os.path.exists(KEY_FILE):
        print(f"Loading keys from {KEY_FILE}...")
        passphrase = keyfile.prompt_passphrase(confirm=False)
        try:
            my_identity, my_keys, encrypted, _state = keyfile.load_keyfile(KEY_FILE, passphrase)
        except Exception as e:
            print(f"Could not open keyfile: {e}")
            sys.exit(1)
        print(f"Welcome back, {my_identity}!")
        if not encrypted:
            print("Keyfile was plaintext. Re-saving it encrypted with your passphrase.")
            keyfile.save_keyfile(KEY_FILE, my_identity, my_keys, passphrase)
        fp = protocol.public_fingerprint(protocol.public_keys_from(my_keys))
        print(f"Your public-key fingerprint: {fp}")
        _ensure_registered()
        return

    print(f"No keys found at {KEY_FILE}. Setup required.")
    username = input("Choose a username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)
    passphrase = keyfile.prompt_passphrase(confirm=True)

    print("Generating RSA-2048, ElGamal-512 (safe prime), and Rabin-512 keys...")
    print("(safe-prime generation can take a few seconds)")
    my_keys = protocol.generate_user_keys()
    my_identity = protocol.normalize_username(username)
    pubs, sig = protocol.sign_identity_bundle(my_identity, my_keys)
    print(f"Your public-key fingerprint: {protocol.public_fingerprint(pubs)}")

    try:
        resp = requests.post(f"{SERVER_URL}/register", json={
            "username": my_identity,
            "public_keys": pubs,
            "identity_sig": sig,
        })
        if resp.status_code == 200:
            print("Registered on server successfully.")
            keyfile.save_keyfile(KEY_FILE, username, my_keys, passphrase)
        else:
            print(f"Registration failed: {resp.text}")
            sys.exit(1)
    except requests.RequestException as e:
        print(f"Server offline or error: {e}")
        sys.exit(1)


def send_msg_flow():
    recipient = input("Recipient username: ").strip()
    if not recipient:
        print("Recipient cannot be empty.")
        return

    try:
        resp = requests.get(f"{SERVER_URL}/keys/{recipient}")
    except requests.RequestException as e:
        print(f"Could not reach server: {e}")
        return

    if resp.status_code != 200:
        print("User not found on server.")
        return

    bundle = resp.json()
    pubs = bundle.get("public_keys", bundle)
    sig = bundle.get("identity_sig")
    if sig and not protocol.verify_identity_bundle(recipient, pubs, sig):
        print("Identity signature failed. Refusing to send.")
        return
    print(f"Recipient fingerprint: {protocol.public_fingerprint(pubs)}")

    print("Select Encryption Scheme:\n1. RSA\n2. ElGamal\n3. Rabin")
    choice = input("Choice: ").strip()
    schemes = {'1': 'rsa', '2': 'elgamal', '3': 'rabin'}
    if choice not in schemes:
        print("Invalid choice.")
        return

    msg_text = input("Message: ")
    if not msg_text:
        print("Message cannot be empty.")
        return

    payload = protocol.hybrid_encrypt(
        msg_text, my_keys, pubs, schemes[choice], my_identity, recipient
    )

    try:
        send_resp = requests.post(f"{SERVER_URL}/send", json={
            "sender": my_identity,
            "recipient": recipient,
            "payload": payload,
        })
    except requests.RequestException as e:
        print(f"Could not reach server: {e}")
        return

    if send_resp.status_code == 200:
        print("Encrypted message sent.")
    else:
        print(f"Send failed: {send_resp.text}")


def check_inbox():
    print(f"\n--- Inbox for {my_identity} ---")
    auth = protocol.inbox_auth_payload(my_identity, my_keys['rsa']['priv'])
    try:
        resp = requests.post(f"{SERVER_URL}/inbox", json=auth)
    except requests.RequestException as e:
        print(f"Could not reach server: {e}")
        return

    if resp.status_code != 200:
        print(f"Error fetching messages: {resp.text}")
        return

    messages = resp.json().get("messages", [])
    if not messages:
        print("No messages.")
        return

    for idx, item in enumerate(messages):
        sender = item['from']
        data = item['payload']
        try:
            key_resp = requests.get(f"{SERVER_URL}/keys/{sender}")
            if key_resp.status_code != 200:
                print(f"[{idx}] From {sender}: sender key not found")
                continue
            bundle = key_resp.json()
            pubs = bundle.get("public_keys", bundle)
            sig = bundle.get("identity_sig")
            if sig and not protocol.verify_identity_bundle(sender, pubs, sig):
                print(f"[{idx}] From {sender}: identity signature failed")
                continue
            plaintext, ok, reason = protocol.hybrid_decrypt(
                data,
                my_keys,
                pubs['rsa'].encode(),
                expected_recipient=my_identity,
            )
            if not ok:
                print(f"[{idx}] From {sender}: failed ({reason})")
                continue
            print(f"[{idx}] From {sender}: {plaintext} (Verified, {data.get('scheme')})")
        except Exception as e:
            print(f"[{idx}] From {sender}: Error ({e})")


def run(keyfile_path="my_private_keys.json"):
    global KEY_FILE
    KEY_FILE = keyfile_path
    print(f"=== Secure Client ({KEY_FILE}) ===")
    load_or_generate_keys()

    while True:
        print("\n1. Send Message  2. Check Inbox  3. Exit")
        c = input("> ").strip()
        if c == '1':
            send_msg_flow()
        elif c == '2':
            check_inbox()
        elif c == '3':
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "my_private_keys.json")
