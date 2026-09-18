# net_utils.py
import json


def send_json(sock, obj):
    """
    Envia uma mensagem JSON terminada por newline.
    Isto evita problemas do TCP, onde um recv(4096) não garante
    receber exatamente uma mensagem completa.
    """
    data = json.dumps(obj).encode("utf-8") + b"\n"
    sock.sendall(data)


def recv_json(file_obj):
    """
    Lê uma linha completa e converte para JSON.
    Deve receber um objeto criado com sock.makefile("r").
    """
    line = file_obj.readline()

    if not line:
        return None

    return json.loads(line)