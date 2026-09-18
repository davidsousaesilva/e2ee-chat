import socket
import threading
import json
import re

from net_utils import send_json, recv_json

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

import os
import base64

HOST = '127.0.0.1'
PORT = 5555

clients = {}        # username -> socket
client_locks = {}   # username -> lock para evitar escritas simultâneas no mesmo socket

SERVER_DATA_DIR = "server_data"
DB_FILE = f"{SERVER_DATA_DIR}/users.json"

CERTS_DIR = f"{SERVER_DATA_DIR}/certs"
USER_CERTS_DIR = f"{CERTS_DIR}/users"

CA_KEY_PATH = f"{CERTS_DIR}/CA.key"
CA_CERT_PATH = f"{CERTS_DIR}/CA.crt"

DEBUG = False

def secure_mkdir(path):
    """
    Cria uma diretoria privada.
    700 = só o dono pode ler, escrever e executar.
    """
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o700)


def secure_write_file(path, data, mode="w", permissions=0o600):
    """
    Escreve um ficheiro e aplica permissões restritas.
    600 = só o dono pode ler e escrever.
    """
    with open(path, mode) as f:
        f.write(data)

    os.chmod(path, permissions)

# ================ CERTIFICADOS ===================

def init_ca():
    secure_mkdir(SERVER_DATA_DIR)
    secure_mkdir(CERTS_DIR)
    secure_mkdir(USER_CERTS_DIR)

    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MyChatCA")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    secure_write_file(
        CA_KEY_PATH,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ),
        mode="wb",
        permissions=0o600
    )

    secure_write_file(
        CA_CERT_PATH,
        cert.public_bytes(serialization.Encoding.PEM),
        mode="wb",
        permissions=0o644
    )

    print("[+] CA created")

def sign_csr(csr_pem, username):
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    csr = x509.load_pem_x509_csr(csr_pem.encode())

    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR")

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username)
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ================= DATABASE =================
def is_valid_username(username):
    return re.fullmatch(r"[a-zA-Z0-9_]{3,32}", username) is not None


def load_users():
    os.makedirs(SERVER_DATA_DIR, exist_ok=True)

    if not os.path.exists(DB_FILE):
        return {}

    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    secure_mkdir(SERVER_DATA_DIR)

    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

    os.chmod(DB_FILE, 0o600)


users_db = load_users()


# ================= PASSWORD =================

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(password.encode())
    return base64.b64encode(salt + key).decode()


def verify_password(password, stored):
    data = base64.b64decode(stored.encode())
    salt = data[:16]
    key = data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    try:
        kdf.verify(password.encode(), key)
        return True
    except:
        return False


# ================= CLIENT HANDLER =================
def send_to_user(target_username, message):
    """
    Envia uma mensagem para um utilizador online.
    Usa lock para evitar que duas threads escrevam ao mesmo tempo no mesmo socket.
    """
    target_conn = clients.get(target_username)
    target_lock = client_locks.get(target_username)

    if not target_conn or not target_lock:
        return False

    with target_lock:
        send_json(target_conn, message)

    return True


def send_response(conn, username, response):
    """
    Envia resposta ao cliente atual.
    Se o utilizador já estiver autenticado, usa o lock dele.
    """
    if username in client_locks:
        with client_locks[username]:
            send_json(conn, response)
    else:
        send_json(conn, response)


def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    username = None
    conn_file = conn.makefile("r", encoding="utf-8")

    try:
        while True:
            message = recv_json(conn_file)

            if message is None:
                break

            response = {}

            msg_type = message.get("type")

            # ================= REGISTER =================
            if msg_type == "register":
                reg_username = message["username"]
                password = message["password"]
                csr = message["csr"]

                if not is_valid_username(reg_username):
                    response = {"status": "error", "message": "invalid username"}

                elif reg_username in users_db:
                    response = {"status": "error", "message": "user exists"}

                else:
                    try:
                        # 1. criar certificado a partir do CSR
                        cert = sign_csr(csr, reg_username)

                        # 2. guardar utilizador
                        users_db[reg_username] = {
                            "password": hash_password(password),
                            "contacts": [],
                            "pending_requests": []
                        }

                        save_users(users_db)

                        # 3. guardar certificado no servidor
                        secure_mkdir(USER_CERTS_DIR)

                        cert_path = f"{USER_CERTS_DIR}/{reg_username}.crt"
                        secure_write_file(cert_path, cert, mode="w", permissions=0o644)

                        # 4. ler certificado da CA
                        with open(CA_CERT_PATH, "r") as f:
                            ca_cert = f.read()

                        # 5. devolver certificado ao cliente
                        response = {
                            "status": "ok",
                            "message": "registered",
                            "certificate": cert,
                            "ca_certificate": ca_cert
                        }

                    except Exception as e:
                        response = {"status": "error", "message": f"registration failed: {e}"}

            # ================= LOGIN =================
            elif msg_type == "login":
                login_username = message["username"]
                password = message["password"]

                if not is_valid_username(login_username):
                    response = {"status": "error", "message": "invalid username"}

                else:
                    user = users_db.get(login_username)

                    if user and verify_password(password, user["password"]):
                        username = login_username
                        clients[username] = conn
                        client_locks[username] = threading.Lock()

                        response = {"status": "ok", "message": "logged in"}
                    else:
                        response = {"status": "error", "message": "invalid credentials"}
                        username = None

            # ================= REQUIRE AUTH =================
            elif not username:
                response = {"status": "error", "message": "not authenticated"}

            # ================= FRIEND REQUEST =================
            elif msg_type == "friend_request":
                target = message["to"]

                if target not in users_db:
                    response = {"status": "error", "message": "user not found"}

                elif target == username:
                    response = {"status": "error", "message": "cannot add yourself"}

                elif username in users_db[target]["contacts"]:
                    response = {"status": "error", "message": "already friends"}

                elif username in users_db[target]["pending_requests"]:
                    response = {"status": "error", "message": "already requested"}

                else:
                    users_db[target]["pending_requests"].append(username)
                    save_users(users_db)

                    response = {"status": "ok", "message": "request sent"}

            # ================= LIST REQUESTS =================
            elif msg_type == "list_requests":
                response = {
                    "status": "ok",
                    "requests": users_db[username]["pending_requests"]
                }

            # ================= ACCEPT REQUEST =================
            elif msg_type == "accept_request":
                requester = message["from"]

                if requester not in users_db[username]["pending_requests"]:
                    response = {"status": "error", "message": "no such request"}

                else:
                    users_db[username]["pending_requests"].remove(requester)

                    users_db[username]["contacts"].append(requester)
                    users_db[requester]["contacts"].append(username)

                    save_users(users_db)

                    response = {"status": "ok", "message": "friend added"}

            # ================= LIST CONTACTS =================
            elif msg_type == "list_contacts":
                response = {
                    "status": "ok",
                    "contacts": users_db[username]["contacts"]
                }

            # ================= GET CERTIFICATE =================
            elif msg_type == "get_certificate":
                target = message["username"]

                if not is_valid_username(target):
                    response = {"status": "error", "message": "invalid username"}

                elif target not in users_db:
                    response = {"status": "error", "message": "user not found"}

                elif target != username and target not in users_db[username]["contacts"]:
                    response = {"status": "error", "message": "not friends"}

                else:
                    cert_path = f"{USER_CERTS_DIR}/{target}.crt"

                    if os.path.exists(cert_path):
                        with open(cert_path, "r") as f:
                            cert = f.read()

                        response = {
                            "status": "ok",
                            "type": "certificate",
                            "username": target,
                            "certificate": cert
                        }
                    else:
                        response = {"status": "error", "message": "certificate not found"}

            # ================= ENCAMINHAMENTO HANDSHAKE ===========

            elif msg_type in ["sts_init", "sts_response", "sts_finalize"]:
                target = message["to"]

                if target not in users_db[username]["contacts"]:
                    response = {"status": "error", "message": "not friends"}

                elif target not in clients:
                    response = {"status": "error", "message": "user offline"}

                else:
                    # O servidor força o remetente real.
                    # Assim o cliente não consegue falsificar "from".
                    message["from"] = username

                    sent = send_to_user(target, message)

                    if sent:
                        response = {"status": "ok", "message": "forwarded"}
                    else:
                        response = {"status": "error", "message": "user offline"}


            # ================= SEND MESSAGE =================
            elif msg_type == "message":
                target = message["to"]

                if target not in users_db[username]["contacts"]:
                    response = {"status": "error", "message": "not friends"}

                elif target not in clients:
                    response = {"status": "error", "message": "user offline"}

                else:
                    # O servidor força o remetente real
                    message["from"] = username

                    sent = send_to_user(target, message)

                    if sent:
                        response = {"status": "ok", "message": "forwarded"}
                    else:
                        response = {"status": "error", "message": "user offline"}

            send_response(conn, username, response)

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        if username and username in clients:
            del clients[username]

        if username and username in client_locks:
            del client_locks[username]

        conn.close()
        print(f"[-] Connection closed {addr}")


# ================= SERVER =================

def start_server():
    init_ca()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[+] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[!] Server stopped manually")