# client_app.py
import requests
import json
import os
import sys
from Crypto.Random import get_random_bytes
from Crypto.Util.number import inverse

# Import your existing crypto modules
from aes_utils import aes_encrypt, aes_decrypt
from rsa_utils import generate_rsa_keys, rsa_encrypt, rsa_decrypt, sign_message, verify_signature
from elgamal_utils import generate_elgamal_keys, elgamal_encrypt, elgamal_decrypt
from rabin_utils import generate_rabin_keys, rabin_encrypt, rabin_decrypt, recover_rabin_aes_key_and_decrypt

SERVER_URL = "http://127.0.0.1:8000"

# Allow user to specify keyfile via command line argument
# Usage: python3 client_app.py [keyfile_name.json]
if len(sys.argv) > 1:
    KEY_FILE = sys.argv[1]
else:
    KEY_FILE = "my_private_keys.json"

# Global state for the running client
my_identity = None
my_keys = {}

def load_or_generate_keys():
    global my_keys, my_identity
    
    if os.path.exists(KEY_FILE):
        print(f"📂 Loading keys from {KEY_FILE}...")
        with open(KEY_FILE, 'r') as f:
            data = json.load(f)
            my_identity = data['username']
            my_keys = data['keys']
        print(f"✅ Welcome back, {my_identity}!")
        return

    print(f"⚙️  No keys found at {KEY_FILE}. Setup required.")
    username = input("Choose a username: ")
    
    print("⚙️  Generating keys (RSA-2048, ElGamal-256, Rabin-256)...")
    rsa_priv, rsa_pub = generate_rsa_keys(2048)
    el_pub, el_priv = generate_elgamal_keys(256)
    r_n, r_p, r_q = generate_rabin_keys(256)

    # Store full keys locally
    my_keys = {
        'rsa': {'priv': rsa_priv.decode(), 'pub': rsa_pub.decode()},
        'elgamal': {'pub': el_pub, 'priv': el_priv},
        'rabin': {'n': r_n, 'p': r_p, 'q': r_q}
    }
    my_identity = username

    # Prepare ONLY public keys for the server
    public_payload = {
        'rsa': my_keys['rsa']['pub'],
        'elgamal': my_keys['elgamal']['pub'],
        'rabin': {'n': my_keys['rabin']['n']} 
    }

    # Register on Server
    try:
        resp = requests.post(f"{SERVER_URL}/register", json={
            "username": username,
            "public_keys": public_payload
        })
        if resp.status_code == 200:
            print("✅ Registered on server successfully.")
            # Save to disk
            with open(KEY_FILE, 'w') as f:
                json.dump({'username': username, 'keys': my_keys}, f)
        else:
            print(f"❌ Registration failed: {resp.text}")
            exit()
    except Exception as e:
        print(f"❌ Server offline or error: {e}")
        exit()

def send_msg_flow():
    recipient = input("Recipient username: ")
    
    # 1. Get Recipient Public Keys from Server
    resp = requests.get(f"{SERVER_URL}/keys/{recipient}")
    if resp.status_code != 200:
        print("❌ User not found on server.")
        return
    
    recipient_keys = resp.json()
    
    print("Select Encryption Scheme:\n1. RSA\n2. ElGamal\n3. Rabin")
    choice = input("Choice: ")
    msg_text = input("Message: ")
    
    # 2. Hybrid Encryption (Locally)
    aes_key = get_random_bytes(16)
    encrypted_msg = aes_encrypt(msg_text, aes_key)
    
    scheme_name = "rsa"
    enc_aes_key = None

    if choice == '1':
        scheme_name = "rsa"
        enc_aes_key = rsa_encrypt(aes_key, recipient_keys['rsa'].encode())
    elif choice == '2':
        scheme_name = "elgamal"
        enc_aes_key = elgamal_encrypt(aes_key, recipient_keys['elgamal'])
    elif choice == '3':
        scheme_name = "rabin"
        enc_aes_key = rabin_encrypt(aes_key, recipient_keys['rabin']['n'])
    
    # 3. Sign (using my private RSA key)
    signature = sign_message(msg_text.encode(), my_keys['rsa']['priv'].encode())

    # 4. Send to Server
    payload = {
        "ciphertext": encrypted_msg,
        "aes_key_enc": enc_aes_key,
        "scheme": scheme_name,
        "signature": signature
    }
    
    requests.post(f"{SERVER_URL}/send", json={
        "sender": my_identity,
        "recipient": recipient,
        "payload": payload
    })
    print("🚀 Encrypted message sent.")

def check_inbox():
    print(f"\n--- Inbox for {my_identity} ---")
    resp = requests.get(f"{SERVER_URL}/inbox/{my_identity}")
    if resp.status_code != 200:
        print("Error fetching messages.")
        return

    messages = resp.json().get("messages", [])
    if not messages:
        print("No messages.")
        return

    for idx, item in enumerate(messages):
        sender = item['from']
        data = item['payload']
        
        aes_key = None
        scheme = data['scheme']
        
        try:
            if scheme == 'rsa':
                aes_key = rsa_decrypt(data['aes_key_enc'], my_keys['rsa']['priv'].encode())
            elif scheme == 'elgamal':
                aes_key = elgamal_decrypt(data['aes_key_enc'], my_keys['elgamal']['priv'], my_keys['elgamal']['pub']['p'])
            elif scheme == 'rabin':
                roots = rabin_decrypt(data['aes_key_enc'], my_keys['rabin']['p'], my_keys['rabin']['q'])
                aes_key, _ = recover_rabin_aes_key_and_decrypt(data['ciphertext'], roots)
            
            if aes_key is None:
                 print(f"[{idx}] From {sender}: Decryption Failed (Invalid Key Recovery)")
                 continue

            # 2. Decrypt Payload
            plaintext = aes_decrypt(data['ciphertext'], aes_key)
            
            # 3. Verify Signature
            key_resp = requests.get(f"{SERVER_URL}/keys/{sender}")
            if key_resp.status_code == 200:
                sender_pub_rsa = key_resp.json()['rsa'].encode()
                is_valid = verify_signature(plaintext.encode(), data['signature'], sender_pub_rsa)
                valid_tag = "✅ Verified" if is_valid else "❌ FAKE SIGNATURE"
                print(f"[{idx}] From {sender}: {plaintext} ({valid_tag})")
            else:
                 print(f"[{idx}] From {sender}: {plaintext} (❓ Sender Key Not Found)")

        except Exception as e:
            print(f"[{idx}] From {sender}: Decryption Error ({e})")

def main():
    print(f"=== Secure Client ({KEY_FILE}) ===")
    load_or_generate_keys()
    
    while True:
        print("\n1. Send Message  2. Check Inbox  3. Exit")
        c = input("> ")
        if c == '1': send_msg_flow()
        elif c == '2': check_inbox()
        elif c == '3': break

if __name__ == "__main__":
    main()