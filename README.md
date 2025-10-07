---

# 🔐 Secure TLS 1.3 Messaging App with Digital Signatures

This project demonstrates a **secure messaging application** simulating a **TLS 1.3 handshake**, including:

* **ECDHE key exchange** for perfect forward secrecy
* **Digital signatures** for handshake and message authentication
* **Session key derivation using HKDF**
* **Encrypted messaging** with AES-GCM or ChaCha20-Poly1305

> ⚠️ Note: This is a **learning/demo implementation** and not production-grade TLS.

---

## **📁 Project Structure**

```
.
├── server.py            # TLS 1.3-style server implementation
├── client.py            # TLS 1.3-style client implementation
├── crypto_utils.py      # Cryptographic primitives (ECDHE, RSA, AES-GCM, HKDF, signatures)
├── README.md            # This file
```

---

## **🛠 Requirements**

* Python **3.10+**
* `cryptography` library
* `pickle` (built-in)
* `os` (built-in)
* `threading` (built-in)
* Optional: `x25519` support is included in `cryptography` library

### **Install dependencies**

```bash
pip install cryptography
```

---

## **🚀 Setup & Usage**

1. **Clone or download the repository**

   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```

2. **Start the server**

   ```bash
   python server.py
   ```

   * Server listens on `localhost:8443`
   * Generates ephemeral ECDHE keys, RSA keys, and self-signed certificate

3. **Start the client**

   ```bash
   python client.py
   ```

   * Connects to server and performs TLS 1.3-style handshake
   * Derives session key and verifies handshake signatures
   * Enters **encrypted chat mode**

4. **Chat**

   * Type messages in the client terminal to send encrypted messages
   * Server prints decrypted messages and verifies signatures
   * Sequence numbers prevent replay attacks

---

## **⚙ How It Works**

1. **Handshake**

   * Client sends `ClientHello` (supported cipher suites + ECDHE pub key)
   * Server sends `ServerHello` + certificate + signature
   * Both derive shared secret via **ECDHE**
   * Session key derived with **HKDF**
   * Client and server exchange **Finished messages** (HMAC over handshake)

2. **Encrypted Messaging**

   * Messages encrypted with **AES-GCM** (or ChaCha20-Poly1305) using session key
   * Messages signed with **RSA-PSS**
   * Server verifies signatures and sends acknowledgement

3. **Security Features**

   * Ephemeral ECDHE for **Perfect Forward Secrecy**
   * RSA signatures for **authentication**
   * HKDF for session key derivation
   * Sequence numbers for **replay attack prevention**

---

## **📝 Notes**

* Self-signed certificates are used for demo purposes; there is no CA validation.
* Cipher suites negotiation is simplified.
* This project is designed for **learning and demonstration of TLS 1.3 concepts**.
* Not recommended for production use.

---


---


