import socket
import threading
import pickle
import os
from crypto_utils import *
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta

HOST = 'localhost'
PORT = 8443

# ---- 1️⃣ Generate Server Keys ----
server_rsa_priv, server_rsa_pub = generate_rsa_keypair()      # For signature
server_ecdhe_priv, server_ecdhe_pub = generate_ecdhe_keys()   # For ECDHE

# ---- Supported Cipher Suites ----
supported_suites = ["AES-GCM-256", "ChaCha20-Poly1305"]

clients = []

# ---- Self-Signed Certificate ----
def generate_self_signed_cert(priv_key, pub_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Demo TLS Server"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        pub_key
    ).serial_number(x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(priv_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)

server_cert = generate_self_signed_cert(server_rsa_priv, server_rsa_pub)

def handle_client(conn, addr):
    print(f"[+] Client connected from {addr}")
    sequence_number = 0

    try:
        # 1️⃣ Receive ClientHello
        client_hello = pickle.loads(conn.recv(4096))
        client_random = client_hello["random"]
        client_ecdhe_pub = serialization.load_pem_public_key(client_hello["ecdhe_pub"])
        client_suites = client_hello.get("cipher_suites", [])
        print("[TLS] Step 1: ClientHello received")

        # 2️⃣ Choose Cipher Suite
        chosen_suite = next((s for s in supported_suites if s in client_suites), None)
        if not chosen_suite:
            print("[ERROR] No common cipher suite!")
            conn.close()
            return

        # 3️⃣ Prepare ServerHello + Signature
        server_random = os.urandom(32)
        handshake_data = client_random + server_random + server_ecdhe_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        signature = sign_data(server_rsa_priv, handshake_data)

        server_hello = {
            "ecdhe_pub": server_ecdhe_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "random": server_random,
            "signature": signature,
            "server_cert": server_cert,
            "cipher_suite": chosen_suite
        }
        conn.send(pickle.dumps(server_hello))
        print(f"[TLS] Step 2: ServerHello + Certificate sent | Cipher: {chosen_suite}")

        # 4️⃣ Derive shared secret + session key
        shared_secret = derive_shared_secret(server_ecdhe_priv, client_ecdhe_pub)
        session_key = hkdf_expand(shared_secret)
        print("[TLS] Step 3: Shared secret derived via ECDHE")
        print("[TLS] Step 4: Session key derived (HKDF)")

        # 5️⃣ Receive Client Finished
        client_finished = pickle.loads(conn.recv(4096))
        client_verify_data = client_finished["verify_data"]
        expected_client_verify = hkdf_hmac(session_key, b"client finished")
        if client_verify_data == expected_client_verify:
            print("[TLS] Step 5: Client Finished verified ✅")
        else:
            print("[TLS] Step 5: Client Finished verification FAILED ❌")
            conn.close()
            return

        # 6️⃣ Send Server Finished
        server_verify_data = hkdf_hmac(session_key, b"server finished")
        conn.send(pickle.dumps({"verify_data": server_verify_data}))
        print("[TLS] Step 6: Server Finished sent ✅")
        print("[TLS] ✅ Handshake complete — Secure channel established")

        clients.append(conn)

        # ---- Encrypted Chat Loop ----
        while True:
            data = conn.recv(4096)
            if not data:
                break

            msg_dict = pickle.loads(data)
            msg_seq = msg_dict.get("seq", -1)
            if msg_seq != sequence_number:
                print(f"[WARNING] Replay attack or out-of-order message!")
                continue
            sequence_number += 1

            ciphertext = msg_dict["ciphertext"]
            sender_pub_bytes = msg_dict["sender_pub"]
            signature = msg_dict["signature"]

            plaintext = decrypt_message(session_key, ciphertext)
            sender_pub = serialization.load_pem_public_key(sender_pub_bytes)

            try:
                verify_signature(sender_pub, signature, plaintext)
                print(f"[TLS] Message verified ✅: {plaintext.decode()}")
                ack = f"Server: Signature OK for '{plaintext.decode()}'"
            except:
                print(f"[TLS] Message signature FAILED ❌: {plaintext.decode()}")
                ack = f"Server: Signature failed for '{plaintext.decode()}'"

            ack_encrypted = encrypt_message(session_key, ack.encode())
            conn.send(ack_encrypted)

            for c in clients:
                if c != conn:
                    c.send(encrypt_message(session_key, plaintext))

    except Exception as e:
        print(f"[ERROR] {e}")

    finally:
        conn.close()
        if conn in clients:
            clients.remove(conn)
        print(f"[-] Client disconnected: {addr}")


# ---- Server Main Loop ----
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)
print(f"[LISTENING] Server on {HOST}:{PORT}")

while True:
    conn, addr = s.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()




