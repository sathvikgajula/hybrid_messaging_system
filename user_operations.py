import base64
from Crypto.Random import get_random_bytes
from aes_utils import aes_encrypt, aes_decrypt
from rsa_utils import generate_rsa_keys, rsa_encrypt, rsa_decrypt
from elgamal_utils import generate_elgamal_keys, elgamal_encrypt, elgamal_decrypt
from rabin_utils import generate_rabin_keys, rabin_encrypt, rabin_decrypt, recover_rabin_aes_key_and_decrypt
from Crypto.Util.number import inverse
from rsa_utils import generate_rsa_keys
from rsa_utils import sign_message
from rsa_utils import verify_signature
from elgamal_utils import generate_elgamal_keys
from rabin_utils import generate_rabin_keys


users = {}
def register_user():
    username = input("Enter username: ")
    if username in users:
        print("User already exists.")
        return
    
    print("Generating RSA (2048-bit), ElGamal (256-bit), and Rabin (256-bit) keys...")

    rsa_priv, rsa_pub = generate_rsa_keys(2048)
    elgamal_pub, elgamal_priv = generate_elgamal_keys(256)
    rabin_n, rabin_p, rabin_q = generate_rabin_keys(256)

    users[username] = {
        'rsa': {'priv': rsa_priv.decode(), 'pub': rsa_pub.decode()},
        'elgamal': {'pubkey': elgamal_pub, 'x': elgamal_priv},
        'rabin': {'n': rabin_n, 'p': rabin_p, 'q': rabin_q}
    }

    print(" User registered with all keys.")



def send_message():
    sender = input("From: ")
    recipient = input("To: ")
    if recipient not in users:
        print("Recipient not found.")
        return
    print("Select Asymmetric Encryption:\n1. RSA\n2. ElGamal\n3. Rabin")
    scheme = input("Choice (1/2/3): ")
    key_size = int(input("Enter key size: "))
    message = input("Enter message: ").encode()
    while True:
        user_key = input("Enter a 16-character AES key (128-bit): ")
        if len(user_key) == 16:
            aes_key = user_key.encode()
            break
        else:
            print("❗ Key must be exactly 16 characters.")
    encrypted_message = aes_encrypt(message.decode(), aes_key)

    if scheme == '1':
        priv, pub = generate_rsa_keys(key_size)
        encrypted_key = rsa_encrypt(aes_key, pub)
        users[recipient]['rsa'] = {'pub': pub.decode(), 'priv': priv.decode()}
    elif scheme == '2':
        pubkey, x = generate_elgamal_keys(key_size)
        encrypted_key = elgamal_encrypt(aes_key, pubkey)
        users[recipient]['elgamal'] = {'pubkey': pubkey, 'x': x}
    elif scheme == '3':
        n, p, q = generate_rabin_keys(key_size)
        encrypted_key = rabin_encrypt(aes_key, n)
        users[recipient]['rabin'] = {'n': n, 'p': p, 'q': q}
    else:
        print("Invalid choice.")
        return

    # Sign the original message
    rsa_priv = users[sender]['rsa']['priv']
    signature = sign_message(message, rsa_priv.encode())

    if 'messages' not in users[recipient]:
        users[recipient]['messages'] = []

    users[recipient]['messages'].append({
        'from': sender,
        'ciphertext': encrypted_message,
        'aes_key': encrypted_key,
        'scheme': scheme,
        'signature': signature
    })

    print("Message sent!")

def view_message():
    user = input("Username: ")
    if user not in users or 'messages' not in users[user] or len(users[user]['messages']) == 0:
        print("No messages.")
        return

    for idx, message in enumerate(users[user]['messages']):
        scheme = message['scheme']
        encrypted_msg = message['ciphertext']
        encrypted_key = message['aes_key']
        sender = message['from']

        if scheme == '1':
            priv = users[user]['rsa']['priv']
            aes_key = rsa_decrypt(encrypted_key, priv.encode())
        elif scheme == '2':
            x = users[user]['elgamal']['x']
            p = users[user]['elgamal']['pubkey']['p']
            aes_key_bytes = bytes([(b * inverse(pow(a, x, p), p)) % p for a, b in encrypted_key])
            aes_key = aes_key_bytes[:16]
        elif scheme == '3':
            p = users[user]['rabin']['p']
            q = users[user]['rabin']['q']
            roots = rabin_decrypt(encrypted_key, p, q)
            aes_key, plaintext = recover_rabin_aes_key_and_decrypt(encrypted_msg, roots)

            if aes_key is None:
                print(f"[{idx+1}] From {sender}: Could not decrypt.")
                continue


        else:
            print(f"[{idx+1}] Unknown encryption scheme.")
            continue

        try:
            plaintext = aes_decrypt(encrypted_msg, aes_key)
            print(f"[{idx+1}] From {sender}: {plaintext} (Encrypted with {'RSA' if scheme=='1' else 'ElGamal' if scheme=='2' else 'Rabin'})")
        except Exception as e:
            print(f"[{idx+1}] Message from {sender} could not be decrypted. Error: {e}")

    signature = message.get('signature')
    rsa_pub = users[sender]['rsa']['pub']

    if verify_signature(plaintext.encode(), signature, rsa_pub.encode()):
        print(f" Signature verified.")
    else:
        print(f" Signature verification failed!")         
