import socket
import threading
import pickle
import os
from crypto_utils import *
from cryptography import x509
from cryptography.hazmat.primitives import serialization

HOST = 'localhost'
PORT = 8443

# ---- Client Keys ----
client_ecdhe_priv, client_ecdhe_pub = generate_ecdhe_keys()
client_rsa_priv, client_rsa_pub = generate_rsa_keypair()
client_random = os.urandom(32)
seq = 0

# ---- Supported Cipher Suites ----
supported_suites = ["AES-GCM-256", "ChaCha20-Poly1305"]

# ---- Send ClientHello ----
client_hello = {
    "ecdhe_pub": client_ecdhe_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
    "random": client_random,
    "cipher_suites": supported_suites
}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send(pickle.dumps(client_hello))
print("[TLS] Step 1: ClientHello sent")

# ---- Receive ServerHello + Verify Certificate ----
server_hello = pickle.loads(sock.recv(4096))
server_random = server_hello["random"]
signature = server_hello["signature"]
server_cert = x509.load_pem_x509_certificate(server_hello["server_cert"])
server_pub_key = server_cert.public_key()
server_ecdhe_pub = serialization.load_pem_public_key(server_hello["ecdhe_pub"])
chosen_suite = server_hello["cipher_suite"]

handshake_data = client_random + server_random + server_hello["ecdhe_pub"]
verify_signature(server_pub_key, signature, handshake_data)
print(f"[TLS] Step 2: ServerHello received and verified ✅ | Cipher: {chosen_suite}")

# ---- Derive Shared Secret + Session Key ----
shared_secret = derive_shared_secret(client_ecdhe_priv, server_ecdhe_pub)
session_key = hkdf_expand(shared_secret)
print("[TLS] Step 3: Shared secret computed")
print("[TLS] Step 4: Session key derived (HKDF)")

# ---- Send Client Finished ----
client_verify_data = hkdf_hmac(session_key, b"client finished")
sock.send(pickle.dumps({"verify_data": client_verify_data}))
print("[TLS] Step 5: Client Finished sent ✅")

# ---- Receive Server Finished ----
server_finished = pickle.loads(sock.recv(4096))
server_verify_data = server_finished["verify_data"]
expected_server_verify = hkdf_hmac(session_key, b"server finished")
if server_verify_data == expected_server_verify:
    print("[TLS] Step 6: Server Finished verified ✅")
    print("[TLS] ✅ Handshake complete — Secure channel established")
else:
    print("[TLS] Step 6: Server Finished FAILED ❌")
    sock.close()
    exit()

# ---- Encrypted Chat Loop ----
def receive_messages():
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            msg = decrypt_message(session_key, data)
            print(f"\n[Server/Other] {msg.decode()}")
        except Exception as e:
            print(f"[ERROR] {e}")
            break

threading.Thread(target=receive_messages, daemon=True).start()

while True:
    msg = input("You: ").encode()
    signature = sign_data(client_rsa_priv, msg)
    msg_dict = {
        "seq": seq,
        "ciphertext": encrypt_message(session_key, msg),
        "signature": signature,
        "sender_pub": client_rsa_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    }
    sock.send(pickle.dumps(msg_dict))
    seq += 1
    print("[TLS] Encrypted message sent ✅")


