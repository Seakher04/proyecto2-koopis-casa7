import hashlib
import json
import os
import secrets
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from seguridad.integridad import calcular_hmac, verificar_hmac
from servidor.comandos import procesar_comando

HOST_DEFECTO = "0.0.0.0"
PUERTO_DEFECTO = 7777

FORMATO_CABECERA = "!IBQ16s"
LONGITUD_CABECERA = 29
LONGITUD_HMAC = 32
MAX_PAYLOAD = 16384

TIPO_HANDSHAKE = 0x01
TIPO_LOGIN = 0x02
TIPO_COMANDO = 0x03
TIPO_RESPUESTA_OK = 0x04
TIPO_ERROR = 0x05

# Parámetros provisionales Diffie-Hellman (RFC 3526 Grupo 14 - 2048 bits)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2

USUARIOS_PROVISIONALES = {
    "jefe": ("jefe123", "jefe"),
    "integrante": ("int123", "integrante"),
    "hacinado": ("hac123", "hacinado"),
}


# =====================================================================
# Adaptadores provisionales para P1 (red) y P2 (handshake, cifrado, login)
# =====================================================================


def _leer_exacto(sock: socket.socket, n: int) -> bytes | None:
    datos = bytearray()
    while len(datos) < n:
        fragmento = sock.recv(n - len(datos))
        if not fragmento:
            return None
        datos.extend(fragmento)
    return bytes(datos)


def _construir_cabecera(longitud: int, tipo: int, nonce: int, iv: bytes) -> bytes:
    return struct.pack(FORMATO_CABECERA, longitud, tipo, nonce, iv)


def _desempaquetar_cabecera(cabecera: bytes) -> tuple[int, int, int, bytes]:
    return struct.unpack(FORMATO_CABECERA, cabecera)


def _leer_paquete(
    sock: socket.socket,
) -> tuple[bytes, int, int, bytes, bytes, bytes] | None:
    cabecera = _leer_exacto(sock, LONGITUD_CABECERA)
    if cabecera is None:
        return None
    longitud, tipo, nonce, iv = _desempaquetar_cabecera(cabecera)
    if longitud > MAX_PAYLOAD:
        return None
    payload_cifrado = _leer_exacto(sock, longitud) if longitud > 0 else b""
    if payload_cifrado is None:
        return None
    hmac_recibido = _leer_exacto(sock, LONGITUD_HMAC)
    if hmac_recibido is None:
        return None
    return cabecera, tipo, nonce, iv, payload_cifrado, hmac_recibido


def _cifrar(datos: bytes, k_cif: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(k_cif), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(datos) + encryptor.finalize()


def _descifrar(datos_cifrados: bytes, k_cif: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(k_cif), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(datos_cifrados) + decryptor.finalize()


def _derivar_claves(secreto_compartido: int) -> tuple[bytes, bytes]:
    s_bytes = secreto_compartido.to_bytes(256, "big")
    k_cif = hashlib.sha256(s_bytes + b"cifrado").digest()
    k_int = hashlib.sha256(s_bytes + b"integridad").digest()
    return k_cif, k_int


def _procesar_handshake(payload_bytes: bytes) -> tuple[str, bytes, bytes] | None:
    try:
        datos = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(datos, dict):
        return None

    version = datos.get("version")
    grupo = datos.get("grupo")
    if (
        isinstance(version, bool)
        or isinstance(grupo, bool)
        or version != 1
        or grupo != 14
    ):
        return None

    param_a_hex = datos.get("A")
    if not isinstance(param_a_hex, str) or not param_a_hex:
        return None
    if param_a_hex.lower().startswith("0x"):
        return None

    try:
        param_a = int(param_a_hex, 16)
    except ValueError:
        return None

    if param_a <= 1 or param_a >= DH_P - 1:
        return None

    priv_b = secrets.randbelow(DH_P - 3) + 2
    pub_b = pow(DH_G, priv_b, DH_P)
    secreto = pow(param_a, priv_b, DH_P)
    k_cif, k_int = _derivar_claves(secreto)
    return format(pub_b, "x"), k_cif, k_int


def _verificar_credenciales(usuario: str, password: str) -> str | None:
    if not isinstance(usuario, str) or not isinstance(password, str):
        return None
    registro = USUARIOS_PROVISIONALES.get(usuario)
    if registro is None:
        return None
    clave_esperada, perfil = registro
    if password == clave_esperada:
        return perfil
    return None


def _enviar_paquete(
    sock: socket.socket,
    tipo: int,
    nonce: int,
    payload_dict: dict,
    k_cif: bytes | None,
    k_int: bytes | None,
) -> None:
    payload_bytes = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    if tipo == TIPO_HANDSHAKE:
        iv = b"\x00" * 16
        payload_final = payload_bytes
        clave_hmac = b""
    else:
        if k_cif is None or k_int is None:
            raise ValueError("Se requieren claves de sesión para enviar paquetes cifrados")
        iv = os.urandom(16)
        payload_final = _cifrar(payload_bytes, k_cif, iv)
        clave_hmac = k_int

    cabecera = _construir_cabecera(len(payload_final), tipo, nonce, iv)
    firma = calcular_hmac(cabecera, payload_final, clave_hmac)
    sock.sendall(cabecera + payload_final + firma)


# =====================================================================
# Flujo principal del servidor de bóveda
# =====================================================================


def manejar_cliente(
    conn: socket.socket,
    servidor_sock: socket.socket | None = None,
) -> None:
    handshake_completado = False
    k_cif: bytes | None = None
    k_int: bytes | None = None
    ultimo_cliente: int | None = None
    nonce_servidor = 0

    sesion = {
        "autenticado": False,
        "perfil": None,
        "intentos_fallidos": 0,
        "cerrar_servidor": False,
    }

    def enviar_respuesta(tipo: int, payload: dict) -> None:
        nonlocal nonce_servidor
        nonce_servidor += 1
        _enviar_paquete(conn, tipo, nonce_servidor, payload, k_cif, k_int)

    try:
        while True:
            paquete = _leer_paquete(conn)
            if paquete is None:
                break

            cabecera, tipo, nonce, iv, payload_cifrado, hmac_recibido = paquete

            # 1. Antes del Handshake
            if not handshake_completado:
                if tipo != TIPO_HANDSHAKE:
                    break
                if nonce != 1 or iv != b"\x00" * 16:
                    break
                if not verificar_hmac(cabecera, payload_cifrado, hmac_recibido, b""):
                    break
                resultado_hs = _procesar_handshake(payload_cifrado)
                if resultado_hs is None:
                    break

                pub_b_hex, k_cif, k_int = resultado_hs
                ultimo_cliente = nonce
                handshake_completado = True
                enviar_respuesta(TIPO_HANDSHAKE, {"grupo": 14, "B": pub_b_hex})
                continue

            # 2. Después del Handshake
            if tipo == TIPO_HANDSHAKE:
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "HANDSHAKE_DUPLICADO",
                        "descripcion": "El handshake ya fue completado",
                    },
                )
                break

            if ultimo_cliente is None or nonce != ultimo_cliente + 1:
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "NONCE_INVALIDO",
                        "descripcion": "Número de secuencia fuera de orden",
                    },
                )
                break
            ultimo_cliente = nonce

            if k_int is None or not verificar_hmac(
                cabecera, payload_cifrado, hmac_recibido, k_int
            ):
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "INTEGRIDAD",
                        "descripcion": "Firma HMAC inválida",
                    },
                )
                break

            try:
                if k_cif is None:
                    raise ValueError("Falta la clave de cifrado")
                texto_plano = _descifrar(payload_cifrado, k_cif, iv)
                payload_dict = json.loads(texto_plano.decode("utf-8"))
                if not isinstance(payload_dict, dict):
                    raise TypeError("El JSON descifrado no es un objeto")
            except (UnicodeDecodeError, TypeError, ValueError):
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "FORMATO_INVALIDO",
                        "descripcion": "El payload descifrado no es JSON válido",
                    },
                )
                break

            # 3. Flujo de Login (0x02)
            if tipo == TIPO_LOGIN:
                if sesion["autenticado"]:
                    enviar_respuesta(
                        TIPO_ERROR,
                        {
                            "codigo": "SESION",
                            "descripcion": "Sesión ya iniciada",
                        },
                    )
                    continue

                usuario = payload_dict.get("usuario")
                password = payload_dict.get("password", payload_dict.get("clave"))
                perfil = (
                    _verificar_credenciales(usuario, password)
                    if isinstance(usuario, str) and isinstance(password, str)
                    else None
                )

                if perfil is None:
                    sesion["intentos_fallidos"] += 1
                    enviar_respuesta(
                        TIPO_ERROR,
                        {
                            "codigo": "CREDENCIALES",
                            "descripcion": "Credenciales inválidas",
                        },
                    )
                    if sesion["intentos_fallidos"] >= 3:
                        break
                    continue

                sesion["autenticado"] = True
                sesion["perfil"] = perfil
                enviar_respuesta(
                    TIPO_RESPUESTA_OK,
                    {
                        "estado": "OK",
                        "mensaje": "Sesión iniciada",
                        "perfil": perfil,
                    },
                )
                continue

            # 4. Flujo de Comandos (0x03)
            if tipo == TIPO_COMANDO:
                tipo_resp, dict_resp = procesar_comando(payload_dict, sesion)
                enviar_respuesta(tipo_resp, dict_resp)

                if sesion.get("cerrar_servidor"):
                    conn.close()
                    if servidor_sock is not None:
                        servidor_sock.close()
                    sys.exit(0)
                continue

            # Cualquier otro tipo no esperado tras el handshake
            enviar_respuesta(
                TIPO_ERROR,
                {
                    "codigo": "SOLICITUD_INVALIDA",
                    "descripcion": "Tipo de mensaje no soportado",
                },
            )
            break
    finally:
        try:
            conn.close()
        except OSError:
            pass


def iniciar_servidor(host: str = HOST_DEFECTO, puerto: int = PUERTO_DEFECTO) -> None:
    servidor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor_sock.bind((host, puerto))
    servidor_sock.listen(5)

    try:
        while True:
            conn, _ = servidor_sock.accept()
            manejar_cliente(conn, servidor_sock)
    finally:
        try:
            servidor_sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    iniciar_servidor()
