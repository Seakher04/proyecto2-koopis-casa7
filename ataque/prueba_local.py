"""
prueba_local.py - Ensayo completo en local, sin tocar ninguna maquina ajena.

Levanta cuatro bovedas mock en 127.0.0.1 y corre todo el toolkit contra ellas:
    puerto 6005  VULNERABLE  (no valida A, no revisa SEQ, HMAC/token/rol ok)
    puerto 6006  SEGURO      (todas las defensas encendidas)
    puerto 6007  SIN_HMAC    (no verifica el HMAC)
    puerto 6008  SIN_TOKEN   (no valida el token de sesion)
    puerto 6009  SIN_ROLES   (el invitado puede escribir)
Asi se ve cada ataque funcionando contra el servidor vulnerable y frenado contra el
seguro: justo el contraste que pide el informe.

Uso:
    python prueba_local.py
Correr con `python` (no `python -I`).
"""

import os
import socket
import subprocess
import sys
import threading
import time

import boveda_local
from boveda_local import Defensas

PY = sys.executable
AQUI = os.path.dirname(os.path.abspath(__file__))


def levantar(puerto, defensas):
    listo = threading.Event()
    threading.Thread(target=boveda_local.servir,
                     args=(puerto, defensas, listo), daemon=True).start()
    listo.wait(timeout=5)


def esperar_puerto(p, intentos=60):
    for _ in range(intentos):
        try:
            socket.create_connection(("127.0.0.1", p), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def correr(titulo, script, puerto):
    print(f"\n########## {titulo}  (puerto {puerto}) ##########")
    subprocess.run([PY, script, "127.0.0.1", str(puerto)], cwd=AQUI)


def main():
    levantar(6005, Defensas())                                      # vulnerable
    levantar(6006, Defensas(valida_a=True, revisa_seq=True, revisa_hmac=True, revisa_token=True))  # seguro
    levantar(6007, Defensas(revisa_hmac=False))                     # sin verificar HMAC
    levantar(6008, Defensas(revisa_token=False))                    # sin validar el token
    levantar(6009, Defensas(revisa_rol=False))                      # sin autorizacion por rol
    for p in (6005, 6006, 6007, 6008, 6009):
        if not esperar_puerto(p):
            print(f"No se pudo levantar la boveda en {p}.")
            return

    correr("recon.py  (calibracion)", "recon.py", 6005)
    correr("ataque.py  clave DH invalida CONTRA SERVIDOR VULNERABLE", "ataque.py", 6005)
    correr("ataque.py  clave DH invalida CONTRA SERVIDOR SEGURO (debe fallar)", "ataque.py", 6006)
    correr("repetir.py  replay CONTRA SERVIDOR VULNERABLE", "repetir.py", 6005)
    correr("repetir.py  replay CONTRA SERVIDOR SEGURO (debe fallar)", "repetir.py", 6006)
    correr("manipular.py  integridad CONTRA SERVIDOR CON HMAC (debe estar protegido)", "manipular.py", 6005)
    correr("manipular.py  integridad CONTRA SERVIDOR SIN_HMAC (debe caer)", "manipular.py", 6007)
    correr("sesion.py  flujo/token/rol CONTRA SERVIDOR SEGURO (debe estar protegido)", "sesion.py", 6005)
    correr("sesion.py  token CONTRA SERVIDOR SIN_TOKEN (debe caer)", "sesion.py", 6008)
    correr("sesion.py  rol CONTRA SERVIDOR SIN_ROLES (debe caer)", "sesion.py", 6009)
    correr("fuzz.py  robustez CONTRA SERVIDOR VULNERABLE", "fuzz.py", 6005)

    print("\n[prueba] fin. Las bovedas de prueba se cierran con este proceso.")


if __name__ == "__main__":
    main()
