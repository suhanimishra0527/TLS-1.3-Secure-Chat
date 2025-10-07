

````markdown
# Custom TLS-like Chat Application (Python)

This project demonstrates a basic client-server secure communication channel implemented in Python, using the `cryptography` library to simulate key aspects of a **TLS handshake** and secure messaging.

It utilizes:
* **X25519 (ECDHE)** for ephemeral key exchange and shared secret generation.
* **HKDF-SHA256** for session key derivation.
* **RSA-PSS with SHA256** for server authentication (digital signature on the handshake).
* **AES-256-GCM (AEAD)** for authenticated, symmetric encryption of chat messages.
* **HMAC-SHA256** for "Finished" handshake verification.

## 📁 Project Structure

The project consists of three main files:

* `crypto_utils.py`: Contains all the cryptographic helper functions (key generation, ECDHE, signing, HKDF, AES-GCM) built on top of the `cryptography` library.
* `server.py`: The main server application that listens for connections, performs the handshake, and handles encrypted chat messages.
* `client.py`: The client application that initiates the connection, performs the handshake, and allows a user to send and receive encrypted messages.

## 🛠️ Setup and Installation

### 1. Prerequisites

You must have **Python 3.6+** installed.

### 2. Install Dependencies

This project requires the `cryptography` library.

```bash
pip install cryptography
````

### 3\. Running the Applications

Since this is a client-server application, you need to run the server first, and then one or more clients.

#### Step A: Start the Server

Open your terminal and run the server script:

```bash
python server.py
```

You should see an output similar to:

```
[LISTENING] Server on localhost:8443
```

#### Step B: Start the Client(s)

Open a **new** terminal window (or multiple for a multi-user chat demo) and run the client script:

```bash
python client.py
```

The client will immediately attempt to connect to the server and begin the handshake.

**Server Output during Handshake:**

```
[+] Client connected from ('127.0.0.1', 50000)
[TLS] Step 1: ClientHello received
[TLS] Step 2: ServerHello + Certificate sent | Cipher: AES-GCM-256
[TLS] Step 3: Shared secret derived via ECDHE
[TLS] Step 4: Session key derived (HKDF)
[TLS] Step 5: Client Finished verified ✅
[TLS] Step 6: Server Finished sent ✅
[TLS] ✅ Handshake complete — Secure channel established
```

**Client Output during Handshake:**

```
[TLS] Step 1: ClientHello sent
[TLS] Step 2: ServerHello received and verified ✅ | Cipher: AES-GCM-256
[TLS] Step 3: Shared secret computed
[TLS] Step 4: Session key derived (HKDF)
[TLS] Step 5: Client Finished sent ✅
[TLS] Step 6: Server Finished verified ✅
[TLS] ✅ Handshake complete — Secure channel established
You:
```

You can now type messages in the client window(s).

## 💬 Usage and Protocol Details

### Handshake Flow (Simulated TLS 1.3/1.2 Hybrid)

1.  **ClientHello:** Client sends its X25519 public key, a random nonce (`client_random`), and supported cipher suites.
2.  **ServerHello:** Server selects a cipher suite, sends its X25519 public key, a random nonce (`server_random`), and its **self-signed RSA certificate**. The server also sends an **RSA-PSS signature** over the concatenated handshake data (`client_random + server_random + server_ecdhe_pub`).
3.  **Authentication:** The client verifies the server's signature using the public key from the certificate.
4.  **Key Exchange:** Both client and server independently compute the **shared secret** using their private X25519 key and the peer's public X25519 key.
5.  **Key Derivation:** Both parties use **HKDF-SHA256** to expand the shared secret into a strong **session key** (32 bytes).
6.  **Finished Messages:** Client and Server exchange HMAC-SHA256 "Finished" messages over specific labels, using the new session key. This confirms that both parties possess the correct session key.

### Secure Messaging

Once the handshake is complete, all messages are secured:

  * **Encryption:** Messages are encrypted using **AES-GCM-256**. The output includes the 12-byte nonce followed by the ciphertext and the 16-byte authentication tag.
  * **Authentication & Integrity:** Every message is signed by the sender using their long-term **RSA key** and **RSA-PSS with SHA256**. This provides a second layer of authentication and message integrity *after* the initial handshake.
  * **Sequence Number:** A simple sequence number is included to detect basic replay attacks or out-of-order delivery (though the current implementation only prevents replay of the very next message).

<!-- end list -->

```
```