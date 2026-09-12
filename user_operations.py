import protocol

users = {}


def register_user():
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    if username in users:
        print("User already exists.")
        return

    print("Generating RSA-2048, ElGamal-512 (safe prime), and Rabin-512 keys...")
    print("(safe-prime generation can take a few seconds)")
    keys = protocol.generate_user_keys()
    users[username] = keys
    fp = protocol.public_fingerprint(protocol.public_keys_from(keys))
    print(f"User registered. Public-key fingerprint: {fp}")


def send_message():
    sender = input("From: ").strip()
    recipient = input("To: ").strip()
    if sender not in users:
        print("Sender not found. Register first.")
        return
    if recipient not in users:
        print("Recipient not found.")
        return

    print("Select Asymmetric Encryption:\n1. RSA\n2. ElGamal\n3. Rabin")
    choice = input("Choice (1/2/3): ").strip()
    schemes = {'1': 'rsa', '2': 'elgamal', '3': 'rabin'}
    if choice not in schemes:
        print("Invalid choice.")
        return

    message = input("Enter message: ")
    if not message:
        print("Message cannot be empty.")
        return

    rec_pubs = protocol.public_keys_from(users[recipient])
    print(f"Recipient fingerprint: {protocol.public_fingerprint(rec_pubs)}")
    payload = protocol.hybrid_encrypt(
        message,
        users[sender],
        rec_pubs,
        schemes[choice],
        sender,
        recipient,
    )
    users[recipient].setdefault('messages', []).append(payload)
    print("Message sent!")


def view_message():
    user = input("Username: ").strip()
    if user not in users or not users[user].get('messages'):
        print("No messages.")
        return

    for idx, payload in enumerate(users[user]['messages']):
        sender = payload.get('sender', '?')
        if sender not in users:
            print(f"[{idx+1}] From {sender}: sender key not found.")
            continue
        plaintext, ok, reason = protocol.hybrid_decrypt(
            payload,
            users[user],
            users[sender]['rsa']['pub'].encode(),
            expected_recipient=user,
        )
        if not ok:
            print(f"[{idx+1}] From {sender}: failed ({reason})")
            continue
        print(f"[{idx+1}] From {sender}: {plaintext} (Encrypted with {payload['scheme']}, signature verified)")
