import socket
import json
import threading
import base64
import os
import time

from net_utils import send_json, recv_json

from crypto.crypto_utils import *

from frontend import *

HOST = '127.0.0.1'
PORT = 5555
CLIENT_DATA_DIR = "client_data"
CA_CERT = None

logged_in = False
username = None
auth_response = None

session_keys = {}  # username -> shared key
pending_dh = {}    # username -> ephemeral private key


def get_user_dir(username):
    return os.path.join(CLIENT_DATA_DIR, username)

def secure_mkdir(path):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o700)


def secure_write_file(path, data, mode="w", permissions=0o600):
    with open(path, mode) as f:
        f.write(data)

    os.chmod(path, permissions)


def save_client_certificates(username, certificate, ca_certificate):
    user_dir = get_user_dir(username)

    secure_mkdir(CLIENT_DATA_DIR)
    secure_mkdir(user_dir)

    secure_write_file(
        os.path.join(user_dir, f"{username}.crt"),
        certificate,
        mode="w",
        permissions=0o644
    )

    secure_write_file(
        os.path.join(user_dir, "ca.crt"),
        ca_certificate,
        mode="w",
        permissions=0o644
    )


def load_own_certificate(username):
    cert_path = os.path.join(get_user_dir(username), f"{username}.crt")

    with open(cert_path, "r") as f:
        return f.read()


def load_ca_certificate(username):
    global CA_CERT

    ca_path = os.path.join(get_user_dir(username), "ca.crt")

    with open(ca_path, "rb") as f:
        CA_CERT = x509.load_pem_x509_certificate(f.read())


# ================= RECEIVE =================
# ================= RECEIVE =================
def receive_messages(sock, sock_file):
    global logged_in, auth_response

    while True:
        try:
            message = recv_json(sock_file)

            if message is None:
                break

            # ================= RESPOSTAS DO SERVIDOR =================
            if "status" in message:
                clean_message = {
                    k: v for k, v in message.items()
                    if k not in ["certificate", "ca_certificate"]
                }

                status = message.get("status")
                server_msg = message.get("message", "")

                # Guardar respostas de autenticação para o auth_menu não ficar preso
                if server_msg in ["logged in", "invalid credentials", "user exists", "registered", "invalid username"]:
                    auth_response = message

                if status == "ok":
                    if server_msg == "registered":
                        save_client_certificates(
                            username,
                            message["certificate"],
                            message["ca_certificate"]
                        )
                        load_ca_certificate(username)
                        print_ok("Registration successful.")
                        print_info("Certificate and CA certificate saved locally.")

                    elif server_msg == "logged in":
                        logged_in = True

                        try:
                            load_ca_certificate(username)
                        except FileNotFoundError:
                            print_warning("CA certificate not found locally. You may need to register again.")

                        print_ok("Login successful.")

                    elif "contacts" in message:
                        contacts = message["contacts"]

                        if contacts:
                            print_info("Contacts:")
                            for contact in contacts:
                                print(f"  - {contact}")
                        else:
                            print_info("You have no contacts yet.")

                    elif "requests" in message:
                        requests = message["requests"]

                        if requests:
                            print_info("Pending friend requests:")
                            for request in requests:
                                print(f"  - {request}")
                        else:
                            print_info("You have no pending friend requests.")

                    else:
                        if server_msg != "forwarded":
                            print_ok(server_msg or clean_message)

                else:
                    print_error(server_msg or clean_message)

                continue

            # ================= HANDSHAKE (STS) =================
            elif message.get("type") == "sts_init":
                sender = message["from"]
                gx = message["gx"]

                print_info(f"STS init received from {sender}.")

                # Gerar chave efémera (garante forward secrecy)
                eph = generate_ephemeral_key()
                gy = serialize_public_key(eph.public_key())

                # Guardar estado do protocolo
                pending_dh[sender] = {
                    "private": eph,
                    "gx": gx,
                    "gy": gy
                }

                # Carregar chave privada para assinar
                priv = load_private_key(username)

                # Carregar certificado próprio
                cert = load_own_certificate(username)

                # Assinar (gy || gx)
                signature = sign_data(priv, (gy + gx).encode())

                # Enviar resposta STS
                send_message(sock, {
                    "type": "sts_response",
                    "to": sender,
                    "from": username,
                    "gy": gy,
                    "signature": base64.b64encode(signature).decode(),
                    "certificate": cert
                })

            elif message.get("type") == "sts_response":
                sender = message["from"]
                gy = message["gy"]
                signature = base64.b64decode(message["signature"])
                cert_pem = message["certificate"]

                print_info(f"STS response received from {sender}.")

                # Obter estado do handshake
                state = pending_dh.get(sender)
                if not state:
                    print_error("No STS state found.")
                    return

                gx = state["gx"]
                eph = state["private"]

                # ================= VALIDAR CERTIFICADO =================
                cert = x509.load_pem_x509_certificate(cert_pem.encode())

                # Verificar se foi assinado pela CA
                verify_cert(cert, CA_CERT)

                # Confirmar que o certificado pertence ao sender
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cn != sender:
                    print_error("Certificate identity mismatch.")
                    return

                pub_key = cert.public_key()

                # ================= VALIDAR ASSINATURA =================
                try:
                    verify_signature(pub_key, signature, (gy + gx).encode())
                except:
                    print_error("Invalid signature from peer.")
                    return

                # Guardar gy para usar na fase final
                state["gy"] = gy

                # ================= DERIVAR CHAVE =================
                peer_pub = load_public_key_from_string(gy)
                key = derive_shared_key(eph, peer_pub)

                session_keys[sender] = key

                # ================= FINALIZAR STS =================
                priv = load_private_key(username)
                cert_self = load_own_certificate(username)

                sig = sign_data(priv, (gx + gy).encode())

                send_message(sock, {
                    "type": "sts_finalize",
                    "to": sender,
                    "from": username,
                    "signature": base64.b64encode(sig).decode(),
                    "certificate": cert_self
                })

                print_ok(f"Secure channel established with {sender}.")

            elif message.get("type") == "sts_finalize":
                sender = message["from"]
                signature = base64.b64decode(message["signature"])
                cert_pem = message["certificate"]

                print_info(f"STS finalize received from {sender}.")

                state = pending_dh.get(sender)
                if not state:
                    print_error("No STS state found.")
                    return

                gx = state["gx"]
                gy = state["gy"]

                # ================= VALIDAR CERTIFICADO =================
                cert = x509.load_pem_x509_certificate(cert_pem.encode())
                verify_cert(cert, CA_CERT)

                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if cn != sender:
                    print_error("Certificate identity mismatch.")
                    return

                pub_key = cert.public_key()

                # ================= VALIDAR ASSINATURA =================
                try:
                    verify_signature(pub_key, signature, (gx + gy).encode())
                except:
                    print_error("Invalid finalize signature.")
                    return

                # ================= DERIVAR CHAVE =================
                eph = state["private"]
                peer_pub = load_public_key_from_string(gx)
                key = derive_shared_key(eph, peer_pub)

                session_keys[sender] = key

                print_ok(f"Secure channel established with {sender}.")

                del pending_dh[sender]

            # ================= MENSAGENS NORMAIS =================
            elif message.get("type") == "message":
                sender = message["from"]

                if sender in session_keys:
                    try:
                        decrypted = decrypt_message(session_keys[sender], message["payload"])

                        print("\n" + "-" * 42)
                        print("New encrypted message")
                        print(f"From: {sender}")
                        print(f"Message: {decrypted}")
                        print("-" * 42)

                    except:
                        print_error(f"Failed to decrypt message from {sender}.")
                else:
                    print_error(f"No session key with {sender}.")

            # ================= FALLBACK =================
            else:
                print_warning(f"Unknown message received: {message}")

        except Exception as e:
            print_error(f"Disconnected from server: {e}")
            break


# ================= SEND =================
def send_message(sock, msg):
    send_json(sock, msg)


# ================= AUTH MENU =================
def auth_menu(sock):
    global username, logged_in, auth_response

    while True:
        choice = show_auth_menu()

        if choice == "1":
            username, password = prompt_credentials()

            if not username or not password:
                print_error("Username and password cannot be empty.")
                continue

            # gerar chave localmente
            public_key = generate_keys(username)
            private_key = load_private_key(username)

            # criar CSR
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, username)
                ]))
                .sign(private_key, hashes.SHA256())
            )

            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

            auth_response = None

            send_message(sock, {
                "type": "register",
                "username": username,
                "password": password,
                "csr": csr_pem
            })

            # Esperar resposta do servidor
            while auth_response is None:
                time.sleep(0.1)

        elif choice == "2":
            username, password = prompt_credentials()

            if not username or not password:
                print_error("Username and password cannot be empty.")
                continue

            auth_response = None

            send_message(sock, {
                "type": "login",
                "username": username,
                "password": password
            })

            # Esperar resposta do servidor sem bloquear para sempre
            while auth_response is None:
                time.sleep(0.1)

            if auth_response.get("status") == "ok":
                return

            username = None

        elif choice == "3":
            print_info("Exiting...")
            sock.close()
            exit()

        else:
            print_error("Invalid option. Please choose 1, 2 or 3.")

# ================= MAIN MENU =================
def main_menu(sock):
    global logged_in

    while logged_in:
        choice = show_main_menu(username)

        if choice == "1":
            send_message(sock, {"type": "list_contacts"})

        elif choice == "2":
            target = prompt_target("Send request to")

            if not target:
                print_error("Username cannot be empty.")
                continue

            send_message(sock, {"type": "friend_request", "to": target})

        elif choice == "3":
            send_message(sock, {"type": "list_requests"})

        elif choice == "4":
            requester = prompt_target("Accept request from")

            if not requester:
                print_error("Username cannot be empty.")
                continue

            send_message(sock, {"type": "accept_request", "from": requester})

        elif choice == "5":
            to_user = input("Send to: ").strip()

            if not to_user:
                print_error("Recipient cannot be empty.")
                continue

            if to_user not in session_keys:
                print_info(f"No secure channel with {to_user}. Starting STS handshake...")

                # gerar chave efémera
                eph = generate_ephemeral_key()
                gx = serialize_public_key(eph.public_key())

                pending_dh[to_user] = {
                    "private": eph,
                    "gx": gx,
                    "gy": None
                }

                send_message(sock, {
                    "type": "sts_init",
                    "to": to_user,
                    "from": username,
                    "gx": gx
                })

                print_info("Waiting for secure channel establishment.")
                print_info("After the channel is established, choose option 5 again to send the message.")
                continue

            content = input("Message: ")

            if not content:
                print_error("Message cannot be empty.")
                continue

            encrypted = encrypt_message(session_keys[to_user], content)

            send_message(sock, {
                "type": "message",
                "to": to_user,
                "from": username,
                "payload": encrypted
            })

            print_ok(f"Encrypted message sent to {to_user}.")

        elif choice == "6":
            print_info("Logging out...")
            logged_in = False
            sock.close()
            break

        else:
            print_error("Invalid option. Please choose a valid menu option.")

# ================= CERTS ================
def verify_cert(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


# ================= MAIN =================
def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print("[+] Connected to server")

    client_file = client.makefile("r", encoding="utf-8")

    # Thread de receção
    thread = threading.Thread(target=receive_messages, args=(client, client_file))
    thread.daemon = True
    thread.start()

    # Primeiro autenticação
    auth_menu(client)

    # Só entra aqui depois de login
    main_menu(client)


if __name__ == "__main__":
    main()