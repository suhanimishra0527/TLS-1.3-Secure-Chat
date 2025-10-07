# crypto_utils.py
import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------
# Key generation / ECDHE (X25519)
# ---------------------------

def generate_ecdhe_keys() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate an ephemeral X25519 keypair for ECDHE-style key exchange.
    Returns (private_key, public_key).
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def derive_shared_secret(priv: x25519.X25519PrivateKey, peer_pub: x25519.X25519PublicKey) -> bytes:
    """
    Perform X25519 key exchange and return the raw shared secret bytes.
    """
    return priv.exchange(peer_pub)


# ---------------------------
# RSA keypair for signing (certificate-like)
# ---------------------------

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA keypair used for signatures.
    Returns (private_key, public_key).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


# ---------------------------
# Sign / Verify helpers (RSA-PSS with SHA256)
# ---------------------------

def sign_data(priv_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign `data` with RSA-PSS + SHA256 and return the signature bytes.
    """
    signature = priv_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(pub_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    """
    Verify signature. Raises cryptography.exceptions.InvalidSignature on failure.
    """
    pub_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# ---------------------------
# HKDF-based session key derivation
# ---------------------------

def hkdf_expand(shared_secret: bytes, length: int = 32, info: bytes = b"handshake data") -> bytes:
    """
    Expand a raw shared secret into a symmetric session key using HKDF-SHA256.
    Returns `length` bytes (default 32 bytes for AES-256).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_secret)


# ---------------------------
# HMAC helper used for "Finished" verify_data
# ---------------------------

def hkdf_hmac(key: bytes, label: bytes) -> bytes:
    """
    Produce an HMAC-SHA256 over `label` using `key`. Used to simulate TLS Finished verify_data.
    Returns the raw HMAC bytes (32 bytes).
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(label)
    return h.finalize()


# ---------------------------
# AEAD encrypt / decrypt (AES-GCM)
# ---------------------------

def _derive_aes_key(session_key: bytes, length: int = 32) -> bytes:
    """
    Derive an AES key from the session_key if needed.
    Here session_key is already HKDF-derived and of appropriate size (32 bytes default).
    This function simply truncates or returns as-is.
    """
    if len(session_key) < length:
        raise ValueError("session_key too short for requested AES key length")
    return session_key[:length]


def encrypt_message(session_key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    """
    Encrypt `plaintext` with AES-GCM using a key derived from `session_key`.
    Returns bytes in the format: nonce(12) || ciphertext_with_tag
    (AESGCM returns ciphertext||tag).
    """
    aes_key = _derive_aes_key(session_key, 32)  # AES-256
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for AES-GCM
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    # Pack nonce + ct together for transmission
    return nonce + ct


def decrypt_message(session_key: bytes, data: bytes, aad: bytes = None) -> bytes:
    """
    Decrypt data produced by encrypt_message.
    Expects data = nonce(12) || ciphertext_with_tag
    Returns the plaintext bytes or raises an exception if authentication fails.
    """
    if len(data) < 12 + 16:  # nonce + tag minimal size check
        raise ValueError("ciphertext too short")

    nonce = data[:12]
    ct = data[12:]
    aes_key = _derive_aes_key(session_key, 32)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ct, aad)
    return plaintext


# ---------------------------
# Convenience: Serialization helpers (optional)
# ---------------------------

def serialize_public_key(pub_key) -> bytes:
    """
    Serialize a public key (RSA or X25519) to PEM (SubjectPublicKeyInfo).
    """
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_bytes: bytes):
    """
    Load a public key (RSA or X25519) from PEM bytes.
    """
    return serialization.load_pem_public_key(pem_bytes)# crypto_utils.py
import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------
# Key generation / ECDHE (X25519)
# ---------------------------

def generate_ecdhe_keys() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate an ephemeral X25519 keypair for ECDHE-style key exchange.
    Returns (private_key, public_key).
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def derive_shared_secret(priv: x25519.X25519PrivateKey, peer_pub: x25519.X25519PublicKey) -> bytes:
    """
    Perform X25519 key exchange and return the raw shared secret bytes.
    """
    return priv.exchange(peer_pub)


# ---------------------------
# RSA keypair for signing (certificate-like)
# ---------------------------

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA keypair used for signatures.
    Returns (private_key, public_key).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


# ---------------------------
# Sign / Verify helpers (RSA-PSS with SHA256)
# ---------------------------

def sign_data(priv_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign `data` with RSA-PSS + SHA256 and return the signature bytes.
    """
    signature = priv_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(pub_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    """
    Verify signature. Raises cryptography.exceptions.InvalidSignature on failure.
    """
    pub_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# ---------------------------
# HKDF-based session key derivation
# ---------------------------

def hkdf_expand(shared_secret: bytes, length: int = 32, info: bytes = b"handshake data") -> bytes:
    """
    Expand a raw shared secret into a symmetric session key using HKDF-SHA256.
    Returns `length` bytes (default 32 bytes for AES-256).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_secret)


# ---------------------------
# HMAC helper used for "Finished" verify_data
# ---------------------------

def hkdf_hmac(key: bytes, label: bytes) -> bytes:
    """
    Produce an HMAC-SHA256 over `label` using `key`. Used to simulate TLS Finished verify_data.
    Returns the raw HMAC bytes (32 bytes).
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(label)
    return h.finalize()


# ---------------------------
# AEAD encrypt / decrypt (AES-GCM)
# ---------------------------

def _derive_aes_key(session_key: bytes, length: int = 32) -> bytes:
    """
    Derive an AES key from the session_key if needed.
    Here session_key is already HKDF-derived and of appropriate size (32 bytes default).
    This function simply truncates or returns as-is.
    """
    if len(session_key) < length:
        raise ValueError("session_key too short for requested AES key length")
    return session_key[:length]


def encrypt_message(session_key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    """
    Encrypt `plaintext` with AES-GCM using a key derived from `session_key`.
    Returns bytes in the format: nonce(12) || ciphertext_with_tag
    (AESGCM returns ciphertext||tag).
    """
    aes_key = _derive_aes_key(session_key, 32)  # AES-256
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for AES-GCM
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    # Pack nonce + ct together for transmission
    return nonce + ct


def decrypt_message(session_key: bytes, data: bytes, aad: bytes = None) -> bytes:
    """
    Decrypt data produced by encrypt_message.
    Expects data = nonce(12) || ciphertext_with_tag
    Returns the plaintext bytes or raises an exception if authentication fails.
    """
    if len(data) < 12 + 16:  # nonce + tag minimal size check
        raise ValueError("ciphertext too short")

    nonce = data[:12]
    ct = data[12:]
    aes_key = _derive_aes_key(session_key, 32)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ct, aad)
    return plaintext


# ---------------------------
# Convenience: Serialization helpers (optional)
# ---------------------------

def serialize_public_key(pub_key) -> bytes:
    """
    Serialize a public key (RSA or X25519) to PEM (SubjectPublicKeyInfo).
    """
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_bytes: bytes):
    """
    Load a public key (RSA or X25519) from PEM bytes.
    """
    return serialization.load_pem_public_key(pem_bytes)


