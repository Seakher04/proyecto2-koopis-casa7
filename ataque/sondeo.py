"""
sondeo.py - Sondeo del handshake y el framing de la Casa 5, SIN necesitar las claves.

Cuando no se puede derivar la clave de sesion (el LOGIN queda bloqueado porque no se
conoce el KDF exacto), igual se puede atacar lo que viaja ANTES de la clave: el
intercambio Diffie-Hellman y el framing. Esta sonda ataca ahi, y todo lo que encuentra
es un hallazgo reportable sin haber entrado a la boveda.

Pruebas:
  1. Valores DH invalidos: manda A = 0, 1, P-1, P y ve si el servidor igual responde
     HELLO_ACK. Si los acepta, no valida el valor publico (vulnerabilidad clasica de DH).
  2. Reuso de la clave DH: hace varios handshakes y compara el B del servidor. Si se
     repite, el servidor reusa su secreto (sin forward secrecy).
  3. Robustez: manda frames mal formados y ve si el servidor se cae o sigue en pie.
  4. Cliente mudo: abre una conexion y no manda nada, y ve si bloquea a otro cliente.

Correr con `python sondeo.py <IP> [puerto]`  (no `python -I`).
"""

import os
import secrets
import socket
import struct
import sys

import casa5
from casa5 import P, G, LARGO_DH

casa5.CONFIG.HS_FORMAT = "raw"   # el servidor real usa raw (lo confirmo recon)


def _hello(host, puerto, A, timeout=4.0):
    """Abre una conexion, manda HELLO con A (256 bytes raw) y devuelve (tipo, payload)."""
    s = socket.create_connection((host, puerto), timeout=timeout)
    try:
        s.sendall(casa5.construir_frame(casa5.HELLO, A.to_bytes(LARGO_DH, "big")))
        s.settimeout(timeout)
        return casa5.recibir_frame(s)
    finally:
        s.close()


def test_valores_invalidos(host, puerto):
    print("[1] Valores DH invalidos (si responde HELLO_ACK, NO valida A)")
    casos = [("A=0", 0), ("A=1", 1), ("A=2 (valido, control)", 2), ("A=P-1", P - 1), ("A=P", P)]
    for nombre, A in casos:
        try:
            tipo, payload = _hello(host, puerto, A)
            if tipo == casa5.HELLO_ACK:
                B = int.from_bytes(payload, "big")
                vb = "B valido" if 2 <= B <= P - 2 else "B INVALIDO"
                print(f"  {nombre:22}-> HELLO_ACK ({vb})  ACEPTADO")
            else:
                print(f"  {nombre:22}-> {casa5.nombre(tipo)}  (rechazado)")
        except Exception as e:
            print(f"  {nombre:22}-> cerro/error ({type(e).__name__})  (rechazado)")
    print("  >> si A=0, 1, P-1 o P salieron ACEPTADO, el servidor no valida el valor DH.")


def test_reuso_b(host, puerto):
    print("[2] Reuso de la clave DH del servidor")
    bs = []
    for _ in range(6):
        try:
            a = secrets.randbelow(P - 3) + 2
            tipo, payload = _hello(host, puerto, pow(G, a, P))
            if tipo == casa5.HELLO_ACK:
                bs.append(int.from_bytes(payload, "big"))
        except Exception:
            pass
    if not bs:
        print("  no se completo ningun handshake")
    elif len(set(bs)) == 1:
        print(f"  B se REPITE en {len(bs)} handshakes -> el servidor reusa su secreto b (sin forward secrecy)")
    else:
        print(f"  B cambia ({len(set(bs))} distintos de {len(bs)}) -> clave efimera (ok)")


def _crudo(host, puerto, datos, espera=1.0):
    """Manda bytes crudos en su propia conexion y reporta que hace el servidor."""
    try:
        s = socket.create_connection((host, puerto), timeout=3.0)
    except OSError as e:
        return f"no conecto ({e})"
    try:
        s.sendall(datos)
        s.settimeout(espera)
        try:
            r = s.recv(4096)
        except socket.timeout:
            return "sin respuesta (se quedo esperando)"
        if not r:
            return "corto"
        return f"respondio tipo {casa5.nombre(r[4])}" if len(r) >= 5 else f"respondio {len(r)} bytes"
    finally:
        s.close()


def test_robustez(host, puerto):
    print("[3] Robustez ante frames mal formados")
    casos = [
        ("Length = 0", struct.pack("!I", 0)),
        ("Length enorme sin cuerpo", struct.pack("!I", 10_000_000)),
        ("frame truncado", struct.pack("!I", 100) + b"\x01\x02\x03"),
        ("tipo 0x99 primero", casa5.construir_frame(0x99, b"\x00")),
        ("HELLO de 1 byte", casa5.construir_frame(casa5.HELLO, b"\x00")),
        ("basura cruda", os.urandom(40)),
    ]
    for etq, d in casos:
        print(f"  {etq:26}: {_crudo(host, puerto, d)}")
    try:
        _hello(host, puerto, pow(G, secrets.randbelow(P - 3) + 2, P))
        print("  >> el servidor SIGUE EN PIE tras el fuzz")
    except Exception as e:
        print(f"  >> el servidor DEJO DE RESPONDER ({type(e).__name__}): posible problema de disponibilidad")


def test_mudo(host, puerto):
    print("[4] Un cliente mudo bloquea a los demas?")
    try:
        mudo = socket.create_connection((host, puerto), timeout=4.0)   # abre y NO manda nada
    except OSError as e:
        print(f"  no se pudo abrir el cliente mudo ({e})")
        return
    try:
        tipo, _ = _hello(host, puerto, pow(G, secrets.randbelow(P - 3) + 2, P), timeout=4.0)
        if tipo == casa5.HELLO_ACK:
            print("  un segundo cliente fue atendido con el mudo colgado -> concurrente (ok)")
        else:
            print(f"  respuesta rara al segundo cliente: {casa5.nombre(tipo)}")
    except (socket.timeout, TimeoutError):
        print("  el segundo cliente NO fue atendido -> un cliente mudo BLOQUEA el servidor (DoS)")
    except Exception as e:
        print(f"  el segundo cliente fallo ({type(e).__name__})")
    finally:
        mudo.close()


def main():
    if len(sys.argv) < 2:
        print("Uso: python sondeo.py <IP> [puerto]")
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Sondeo de handshake/framing contra {host}:{puerto} (Casa 5) ===")
    print("    (no necesita las claves de sesion)\n")
    test_valores_invalidos(host, puerto)
    print()
    test_reuso_b(host, puerto)
    print()
    test_robustez(host, puerto)
    print()
    test_mudo(host, puerto)


if __name__ == "__main__":
    main()
