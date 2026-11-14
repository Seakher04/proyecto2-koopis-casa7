"""Cliente Custodio para conectarse por TCP a la Boveda."""

import socket
import sys

from red.protocolo import PUERTO_DEFECTO


# TODO: cambiar "127.0.0.1" por la IP del lab (o pasarla por argumento al ejecutar)
def iniciar_cliente(host="127.0.0.1", puerto=PUERTO_DEFECTO):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, puerto))
        except OSError as exc:
            print(f"[Custodio] No se pudo conectar a {host}:{puerto} ({exc})")
            return
        print(f"[Custodio] Conectado a {host}:{puerto}")
        # TODO: ejecutar handshake (0x01), login (0x02) y ciclo de comandos (0x03/0x04/0x05)


if __name__ == "__main__":
    destino = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    puerto_arg = int(sys.argv[2]) if len(sys.argv) > 2 else PUERTO_DEFECTO
    iniciar_cliente(destino, puerto_arg)
