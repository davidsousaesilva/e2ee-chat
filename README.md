# E2EE Chat

A client-server chat application with End-to-End Encryption, built for the Information Systems Security course at the University of Minho. The server acts as a self-signed Certificate Authority and message relay; it never has access to message content or session keys.

## Security design

- PKI with a self-signed CA issuing X.509 certificates to registered users
- Station-to-Station (STS) protocol for authenticated session-key establishment (ECDH + HKDF)
- AES-GCM for message encryption, PBKDF2-HMAC-SHA256 for password storage
- Forward secrecy through ephemeral ECDH keys per session

## Tech stack

Python, `cryptography` library, TCP sockets.

## Run locally

Start the server:

```bash
python code/server.py
```

Start a client (new terminal, one per user):

```bash
python code/client.py
```

## Team

- David Sousa e Silva
- João Rafael Martins da Costa
- Tomás Barroso Ramalhete
