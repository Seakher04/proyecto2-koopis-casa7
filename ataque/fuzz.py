"""
fuzz.py - Sonda de robustez / disponibilidad contra la Boveda de la Casa 5.

Manda una tanda de frames mal formados, cada uno en su propia conexion, y mira que hace
el servidor: responde con un codigo de error, corta limpio, o se queda sin responder. Al
final comprueba que el servidor SIGUE atendiendo con un handshake normal. No inunda ni
satura: es una prueba de manejo de errores, no un ataque de denegacion de servicio.

Antes de correr: calibrar con recon.py y pegar el CONFIG en casa5.py.
Correr con `python fuzz.py <IP> [puerto]`  (no `python -I`).
"""

import os
import socket
import struct
import sys

import casa5


def _mandar(host, puerto, datos, espera=1.0):
    """Abre una conexion, manda bytes crudos, lee lo que vuelva y cierra."""
    try:
        s = socket.create_connection((host, puerto), timeout=3.0)
    except OSError as e:
        return f"no conecto ({e})"
    try:
        s.sendall(datos)
        s.settimeout(espera)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            return "sin respuesta (se quedo esperando, no corto)"
        if not resp:
            return "corto la conexion"
        if len(resp) >= 5:
            return f"respondio un frame tipo {casa5.nombre(resp[4])}"
        return f"respondio {len(resp)} bytes"
    finally:
        s.close()


def correr(host, puerto):
    casos = [
        ("Length = 0 (invalido)", struct.pack("!I", 0)),
        ("Length enorme sin cuerpo", struct.pack("!I", 10_000_000)),
        ("frame truncado (dice 100, manda 3)", struct.pack("!I", 100) + b"\x01\x02\x03"),
        ("tipo 0x99 como primer frame", casa5.construir_frame(0x99, b"\x00")),
        ("HELLO con payload de 20 KB no-JSON", casa5.construir_frame(casa5.HELLO, b"A" * 20000)),
        ("basura cruda", os.urandom(48)),
    ]
    for etiqueta, datos in casos:
        print(f"  {etiqueta:38}: {_mandar(host, puerto, datos)}")

    print("  ----")
    try:
        with casa5.ClienteCasa5(host, puerto) as c:
            c.handshake()
        print("  >> el servidor SIGUE EN PIE (un handshake normal anda tras el fuzz).")
    except Exception as e:
        print(f"  >> el servidor DEJO DE RESPONDER ({type(e).__name__}): posible fallo de disponibilidad.")


def main():
    if len(sys.argv) < 2:
        print("Uso: python fuzz.py <IP> [puerto]")
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Sonda de robustez contra {host}:{puerto} (Casa 5) ===")
    correr(host, puerto)


if __name__ == "__main__":
    main()
