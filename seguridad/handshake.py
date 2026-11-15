"""Punto 5: handshake Diffie-Hellman y derivacion de las claves de sesion."""

import hashlib
import json
import re
import secrets

# Grupo 14 del RFC 3526: primo de 2048 bits y generador 2
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
GRUPO = 14
VERSION = 1
LARGO_S = 256  # bytes del secreto compartido (2048 bits)


def derivar_claves(secreto):
    """Saca K_cif y K_int, de 32 bytes cada una, del secreto compartido."""
    s_bytes = secreto.to_bytes(LARGO_S, "big")
    k_cif = hashlib.sha256(s_bytes + b"cifrado").digest()
    k_int = hashlib.sha256(s_bytes + b"integridad").digest()
    return k_cif, k_int


def _leer_publico(texto):
    """Pasa A o B de hexadecimal a entero y revisa que este entre 2 y p - 2."""
    if not isinstance(texto, str) or not re.fullmatch(r"[0-9a-fA-F]{1,512}", texto):
        return None
    valor = int(texto, 16)
    if not 2 <= valor <= P - 2:
        return None
    return valor


def iniciar_handshake():
    """Cliente, paso 1: devuelve (a, payload del 0x01). Guardar a hasta que llegue B."""
    a = secrets.randbelow(P - 3) + 2
    payload = {"version": VERSION, "grupo": GRUPO, "A": format(pow(G, a, P), "x")}
    return a, payload


def procesar_handshake(payload_bytes):
    """Servidor: lee el 0x01 del cliente y devuelve (B en hex, K_cif, K_int) o None."""
    try:
        datos = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(datos, dict):
        return None
    version = datos.get("version")
    grupo = datos.get("grupo")
    # type(...) is int descarta bool (True == 1) y float (14.0 == 14)
    if type(version) is not int or type(grupo) is not int or version != VERSION or grupo != GRUPO:
        return None
    a_pub = _leer_publico(datos.get("A"))
    if a_pub is None:
        return None
    b = secrets.randbelow(P - 3) + 2
    k_cif, k_int = derivar_claves(pow(a_pub, b, P))
    return format(pow(G, b, P), "x"), k_cif, k_int


def terminar_handshake(a, payload_bytes):
    """Cliente, paso 3: lee el 0x01 del servidor y devuelve (K_cif, K_int) o None."""
    try:
        datos = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(datos, dict) or datos.get("grupo") != GRUPO:
        return None
    b_pub = _leer_publico(datos.get("B"))
    if b_pub is None:
        return None
    return derivar_claves(pow(b_pub, a, P))
