from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

import os
import base64

CLIENT_DATA_DIR = "client_data"

def get_user_dir(username):
    return os.path.join(CLIENT_DATA_DIR, username)

def secure_mkdir(path):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o700)


def secure_write_file(path, data, mode="wb", permissions=0o600):
    with open(path, mode) as f:
        f.write(data)

    os.chmod(path, permissions)


# ================= IDENTIDADE =================

def generate_keys(username):
    user_dir = get_user_dir(username)
    secure_mkdir(CLIENT_DATA_DIR)
    secure_mkdir(user_dir)

    private_key = ec.generate_private_key(ec.SECP256R1())

    private_key_path = os.path.join(user_dir, f"{username}_private.pem")
    public_key_path = os.path.join(user_dir, f"{username}_public.pem")

    secure_write_file(
        private_key_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ),
        mode="wb",
        permissions=0o600
    )

    public_key = private_key.public_key()

    secure_write_file(
        public_key_path,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        mode="wb",
        permissions=0o644
    )

    return public_key


def load_private_key(username):
    user_dir = get_user_dir(username)
    private_key_path = os.path.join(user_dir, f"{username}_private.pem")

    with open(private_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key_from_string(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# ================= ECDH =================

def generate_ephemeral_key():
    return ec.generate_private_key(ec.SECP256R1())


def derive_shared_key(private_key, peer_public_key):
    shared = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derivar chave forte (HKDF)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat-e2ee',
    ).derive(shared)

    return derived_key


# ============= ENC/DEC ====================
def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_message(key, data):
    raw = base64.b64decode(data.encode())

    nonce = raw[:12]
    ciphertext = raw[12:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode()

# ============ CERTIFICATES =======================
def sign_data(private_key, data: bytes):
    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

def verify_signature(public_key, signature, data):
    public_key.verify(
        signature,
        data,
        ec.ECDSA(hashes.SHA256())
    )