"""Punto 6: autentificacion. Login con PBKDF2 y archivo de usuarios.

Crear usuarios desde la raiz del repo: python -m seguridad.login <archivo.txt> <usuario> <perfil>
"""

import hashlib
import hmac
import os
import re
import secrets

ITERACIONES = 200_000
LARGO_SAL = 16
MAX_CLAVE = 128
MIN_CLAVE_NUEVA = 12
PERFILES = ("integrante", "jefe", "hacinado")
PATRON_USUARIO = re.compile(r"[A-Za-z0-9_.-]{1,32}")

# Sal de relleno: si el usuario no existe se calcula igual un hash, para tardar lo mismo
_SAL_RELLENO = secrets.token_bytes(LARGO_SAL)


def hash_clave(clave, sal):
    """PBKDF2-HMAC-SHA256 de la clave con su sal."""
    return hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), sal, ITERACIONES)


def cargar_usuarios(ruta):
    """Lee el .txt de usuarios. Cada linea: usuario:perfil:sal:hash (sal y hash en hexadecimal)."""
    usuarios = {}
    with open(ruta, encoding="utf-8") as archivo:
        for numero, linea in enumerate(archivo, 1):
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split(":")
            if len(partes) != 4 or partes[1] not in PERFILES:
                raise ValueError(f"{ruta}, linea {numero}: formato invalido")
            usuario, perfil, sal_hex, hash_hex = partes
            usuarios[usuario] = (perfil, bytes.fromhex(sal_hex), bytes.fromhex(hash_hex))
    return usuarios


def agregar_usuario(ruta, usuario, clave, perfil):
    """Agrega un usuario al .txt con una sal nueva. La clave nunca se guarda."""
    if not PATRON_USUARIO.fullmatch(usuario):
        raise ValueError("Usuario: de 1 a 32 letras, numeros, punto, guion o guion bajo")
    if perfil not in PERFILES:
        raise ValueError(f"Perfil: uno de {PERFILES}")
    if not MIN_CLAVE_NUEVA <= len(clave) <= MAX_CLAVE:
        raise ValueError(f"La clave debe tener entre {MIN_CLAVE_NUEVA} y {MAX_CLAVE} caracteres")
    if os.path.exists(ruta) and usuario in cargar_usuarios(ruta):
        raise ValueError("Ese usuario ya existe")
    # En un clon nuevo la carpeta (servidor/datos) no existe: se crea si falta
    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    sal = secrets.token_bytes(LARGO_SAL)
    with open(ruta, "a", encoding="utf-8") as archivo:
        archivo.write(f"{usuario}:{perfil}:{sal.hex()}:{hash_clave(clave, sal).hex()}\n")


def verificar_credenciales(usuarios, usuario, clave):
    """Devuelve el perfil si usuario y clave calzan, o None. Tarda lo mismo si el usuario no existe."""
    registro = usuarios.get(usuario) if isinstance(usuario, str) else None
    clave_ok = isinstance(clave, str) and 1 <= len(clave) <= MAX_CLAVE
    if registro is None or not clave_ok:
        hash_clave(clave if clave_ok else "-", _SAL_RELLENO)
        return None
    perfil, sal, guardado = registro
    if hmac.compare_digest(hash_clave(clave, sal), guardado):
        return perfil
    return None


if __name__ == "__main__":
    import getpass
    import sys

    if len(sys.argv) != 4:
        print("Uso: python -m seguridad.login <archivo.txt> <usuario> <perfil>")
        sys.exit(1)
    ruta, usuario, perfil = sys.argv[1:]
    clave = getpass.getpass("Clave (Enter para generar una al azar): ")
    if not clave:
        clave = secrets.token_urlsafe(12)
        print("Clave generada (anotala, no se vuelve a mostrar):", clave)
    elif getpass.getpass("Repeti la clave: ") != clave:
        print("Las claves no coinciden")
        sys.exit(1)
    try:
        agregar_usuario(ruta, usuario, clave, perfil)
    except ValueError as error:
        print("Error:", error)
        sys.exit(1)
    print(f"Usuario {usuario} ({perfil}) agregado a {ruta}")
