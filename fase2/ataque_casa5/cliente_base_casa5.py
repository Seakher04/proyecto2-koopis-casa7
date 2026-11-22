"""Cliente base legitimo para el protocolo 'La ratonera' (Casa 5).

Implementa la especificacion publica de Casa 5 (TCP 6005):
- Framing: <Length: 4B uint32 big-endian><Type: 1B uint8><Payload: Length - 1 B>
- Handshake: Diffie-Hellman Grupo 14 (RFC 3526), enteros de 256 bytes big-endian
- Confidencialidad: AES-256-CBC con padding PKCS#7 e IV aleatorio de 16 bytes
- Integridad: Encrypt-then-MAC con HMAC-SHA256(clave_mac, tipo + IV + cifrado)
- Anti-repeticion: contador SEQ estrictamente creciente dentro del JSON cifrado

IMPORTANTE:
En el PDF publico de Casa 5 quedaron dos detalles sin especificar por completo:
  1. Las etiquetas literales exactas del KDF (Seccion 5).
  2. Los nombres exactos de los campos JSON de LOGIN y comandos (Seccion 10).
Esas constantes estan concentradas arriba con '# TODO' para ajustarlas en cuanto
Casa 5 o la profesora confirmen el formato exacto.
"""

import argparse
import hashlib
import hmac
import json
import secrets
import socket
import struct

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from seguridad.handshake import G as DH_G
from seguridad.handshake import P as DH_P

PUERTO_CASA5 = 6005
USUARIO_ASILO = "ratonton"
CLAVE_ASILO = "ratoncinado"

TAMANO_DH_BYTES = 256
TAMANO_IV = 16
TAMANO_HMAC = 32
TAMANO_MAX_TRAMA = 1024 * 1024  # Tope defensivo local (1 MB)

# Tipos de mensaje <Type> segun la especificacion de Casa 5 (pags. 2-3)
TYPE_HELLO = 0x01
TYPE_HELLO_ACK = 0x02

TYPE_LOGIN = 0x10
TYPE_LOGIN_OK = 0x11
TYPE_LOGIN_FAIL = 0x12

TYPE_CMD_ASK = 0x20
TYPE_CMD_ADD = 0x21
TYPE_CMD_DEL = 0x22
TYPE_CMD_END = 0x23

TYPE_RET_OK = 0x30
TYPE_RET_UNKN = 0x31
TYPE_RET_EXIST = 0x32

TYPE_ERR_TYPE = 0xF0
TYPE_ERR_MSG = 0xF1
TYPE_ERR_LEN = 0xF2
TYPE_ERR_SESION = 0xF3
TYPE_ERR_ALLOW = 0xF4
TYPE_ERR_SERV = 0xF5

NOMBRES_TIPO = {
    TYPE_HELLO: "HELLO",
    TYPE_HELLO_ACK: "HELLO_ACK",
    TYPE_LOGIN: "LOGIN",
    TYPE_LOGIN_OK: "LOGIN_OK",
    TYPE_LOGIN_FAIL: "LOGIN_FAIL",
    TYPE_CMD_ASK: "CMD_ASK",
    TYPE_CMD_ADD: "CMD_ADD",
    TYPE_CMD_DEL: "CMD_DEL",
    TYPE_CMD_END: "CMD_END",
    TYPE_RET_OK: "RET_OK",
    TYPE_RET_UNKN: "RET_UNKN",
    TYPE_RET_EXIST: "RET_EXIST",
    TYPE_ERR_TYPE: "ERR_TYPE",
    TYPE_ERR_MSG: "ERR_MSG",
    TYPE_ERR_LEN: "ERR_LEN",
    TYPE_ERR_SESION: "ERR_SESION",
    TYPE_ERR_ALLOW: "ERR_ALLOW",
    TYPE_ERR_SERV: "ERR_SERV",
}

# =====================================================================
# TODO: Confirmar estos valores con Casa 5 / la profesora
# =====================================================================
# Seccion 5: etiquetas exactas de derivacion de claves (C->S y S->C)
KDF_ENC_C2S = b"ENC_C2S"
KDF_MAC_C2S = b"MAC_C2S"
KDF_ENC_S2C = b"ENC_S2C"
KDF_MAC_S2C = b"MAC_S2C"

# Seccion 10 (faltante en el PDF): nombres exactos de campos JSON
CAMPO_SEQ = "seq"
CAMPO_TOKEN = "token"
CAMPO_USUARIO = "user"
CAMPO_CLAVE_LOGIN = "password"
CAMPO_KEY = "key"
CAMPO_VALUE = "value"


class ErrorRatonera(Exception):
    pass


def recibir_exacto(sock: socket.socket, cantidad: int) -> bytes:
    """Lee exactamente `cantidad` bytes del flujo TCP."""
    partes = []
    recibidos = 0
    while recibidos < cantidad:
        bloque = sock.recv(cantidad - recibidos)
        if not bloque:
            raise ConnectionError("Conexion cerrada por Casa 5 antes de completar la trama")
        partes.append(bloque)
        recibidos += len(bloque)
    return b"".join(partes)


def enviar_trama(sock: socket.socket, tipo: int, payload: bytes) -> None:
    """Envia <Length: 4B><Type: 1B><Payload>, donde Length = 1 + len(Payload)."""
    longitud = 1 + len(payload)
    cabecera = struct.pack("!IB", longitud, tipo)
    sock.sendall(cabecera + payload)


def recibir_trama(sock: socket.socket) -> tuple[int, bytes]:
    """Lee una trama completa <Length><Type><Payload>."""
    raw_len = recibir_exacto(sock, 4)
    (longitud,) = struct.unpack("!I", raw_len)
    if longitud < 1 or longitud > TAMANO_MAX_TRAMA:
        raise ErrorRatonera(f"Longitud fuera de rango: {longitud}")
    cuerpo = recibir_exacto(sock, longitud)
    return cuerpo[0], cuerpo[1:]


def derivar_claves(secreto_k: int) -> dict[str, bytes]:
    """Deriva claves de cifrado y MAC direccionales usando SHA-256."""
    k_bytes = secreto_k.to_bytes(TAMANO_DH_BYTES, "big")
    return {
        "enc_c2s": hashlib.sha256(k_bytes + KDF_ENC_C2S).digest(),
        "mac_c2s": hashlib.sha256(k_bytes + KDF_MAC_C2S).digest(),
        "enc_s2c": hashlib.sha256(k_bytes + KDF_ENC_S2C).digest(),
        "mac_s2c": hashlib.sha256(k_bytes + KDF_MAC_S2C).digest(),
    }


def cifrar_cbc_pkcs7(datos: bytes, clave_enc: bytes) -> tuple[bytes, bytes]:
    """Aplica PKCS#7 y cifra con AES-256-CBC usando un IV aleatorio de 16 bytes."""
    iv = secrets.token_bytes(TAMANO_IV)
    padder = padding.PKCS7(128).padder()
    relleno = padder.update(datos) + padder.finalize()
    cifrador = Cipher(algorithms.AES(clave_enc), modes.CBC(iv)).encryptor()
    cifrado = cifrador.update(relleno) + cifrador.finalize()
    return iv, cifrado


def descifrar_cbc_pkcs7(iv: bytes, cifrado: bytes, clave_enc: bytes) -> bytes:
    """Descifra AES-256-CBC y remueve el relleno PKCS#7."""
    descifrador = Cipher(algorithms.AES(clave_enc), modes.CBC(iv)).decryptor()
    relleno = descifrador.update(cifrado) + descifrador.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(relleno) + unpadder.finalize()


def calcular_mac(clave_mac: bytes, tipo: int, iv: bytes, cifrado: bytes) -> bytes:
    """Calcula HMAC-SHA256(clave_mac, tipo + IV + JSON_cifrado)."""
    return hmac.new(clave_mac, bytes([tipo]) + iv + cifrado, hashlib.sha256).digest()


class ClienteRatonera:
    """Cliente estandar del protocolo La ratonera (Casa 5)."""

    def __init__(self, host: str, puerto: int = PUERTO_CASA5, timeout: float = 10.0) -> None:
        self.host = host
        self.puerto = puerto
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.claves: dict[str, bytes] | None = None
        self.seq = 0
        self.token: str | None = None

    def conectar(self) -> None:
        self.sock = socket.create_connection((self.host, self.puerto), timeout=self.timeout)

    def cerrar(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def hacer_handshake(self) -> None:
        assert self.sock is not None
        priv_a = secrets.randbelow(DH_P - 3) + 2
        pub_a = pow(DH_G, priv_a, DH_P)
        enviar_trama(self.sock, TYPE_HELLO, pub_a.to_bytes(TAMANO_DH_BYTES, "big"))

        tipo, payload = recibir_trama(self.sock)
        if tipo != TYPE_HELLO_ACK:
            raise ErrorRatonera(f"Respuesta inesperada en handshake: {tipo:#x} ({NOMBRES_TIPO.get(tipo, '?')})")
        if len(payload) != TAMANO_DH_BYTES:
            raise ErrorRatonera(f"Tamano invalido de B en HELLO_ACK: {len(payload)} bytes")

        pub_b = int.from_bytes(payload, "big")
        if not 2 <= pub_b <= DH_P - 2:
            raise ErrorRatonera("Valor publico B fuera de rango [2, p-2]")

        secreto_k = pow(pub_b, priv_a, DH_P)
        self.claves = derivar_claves(secreto_k)

    def _enviar_cifrado(self, tipo: int, datos: dict) -> None:
        assert self.sock is not None and self.claves is not None
        self.seq += 1
        cuerpo = {CAMPO_SEQ: self.seq, **datos}
        if self.token is not None and tipo != TYPE_LOGIN:
            cuerpo.setdefault(CAMPO_TOKEN, self.token)

        json_bytes = json.dumps(cuerpo, ensure_ascii=False).encode("utf-8")
        iv, cifrado = cifrar_cbc_pkcs7(json_bytes, self.claves["enc_c2s"])
        mac = calcular_mac(self.claves["mac_c2s"], tipo, iv, cifrado)
        enviar_trama(self.sock, tipo, iv + cifrado + mac)

    def _recibir_cifrado(self) -> tuple[int, dict]:
        assert self.sock is not None and self.claves is not None
        tipo, payload = recibir_trama(self.sock)
        if len(payload) < TAMANO_IV + TAMANO_HMAC:
            raise ErrorRatonera(f"Trama cifrada demasiado corta ({len(payload)} bytes)")

        iv = payload[:TAMANO_IV]
        mac_recibido = payload[-TAMANO_HMAC:]
        cifrado = payload[TAMANO_IV:-TAMANO_HMAC]

        mac_esperado = calcular_mac(self.claves["mac_s2c"], tipo, iv, cifrado)
        if not hmac.compare_digest(mac_esperado, mac_recibido):
            raise ErrorRatonera("HMAC invalido en respuesta del servidor")

        claro = descifrar_cbc_pkcs7(iv, cifrado, self.claves["enc_s2c"])
        return tipo, json.loads(claro.decode("utf-8"))

    def iniciar_sesion(self, usuario: str = USUARIO_ASILO, clave: str = CLAVE_ASILO) -> tuple[int, dict]:
        self._enviar_cifrado(TYPE_LOGIN, {CAMPO_USUARIO: usuario, CAMPO_CLAVE_LOGIN: clave})
        tipo, resp = self._recibir_cifrado()
        if tipo == TYPE_LOGIN_OK and isinstance(resp, dict) and CAMPO_TOKEN in resp:
            self.token = resp[CAMPO_TOKEN]
        return tipo, resp

    def consultar(self, clave: str = "") -> tuple[int, dict]:
        self._enviar_cifrado(TYPE_CMD_ASK, {CAMPO_KEY: clave})
        return self._recibir_cifrado()

    def agregar(self, clave: str, valor: str) -> tuple[int, dict]:
        self._enviar_cifrado(TYPE_CMD_ADD, {CAMPO_KEY: clave, CAMPO_VALUE: valor})
        return self._recibir_cifrado()

    def borrar(self, clave: str) -> tuple[int, dict]:
        self._enviar_cifrado(TYPE_CMD_DEL, {CAMPO_KEY: clave})
        return self._recibir_cifrado()

    def finalizar_sesion(self) -> tuple[int, dict]:
        self._enviar_cifrado(TYPE_CMD_END, {})
        return self._recibir_cifrado()


def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente base legitimo para Casa 5 (La ratonera).")
    parser.add_argument("host", help="IP del servidor de Casa 5")
    parser.add_argument("--puerto", type=int, default=PUERTO_CASA5)
    parser.add_argument("--usuario", default=USUARIO_ASILO)
    parser.add_argument("--clave", default=CLAVE_ASILO)
    args = parser.parse_args()

    cli = ClienteRatonera(args.host, args.puerto)
    try:
        cli.conectar()
        print(f"[Casa5] Conectado a {args.host}:{args.puerto}")
        cli.hacer_handshake()
        print("[Casa5] Handshake Diffie-Hellman completado")
        tipo, resp = cli.iniciar_sesion(args.usuario, args.clave)
        print(f"[Casa5] Respuesta LOGIN ({tipo:#x} {NOMBRES_TIPO.get(tipo, '?')}): {resp}")
    except (OSError, ErrorRatonera, ValueError) as exc:
        print(f"[Casa5] Error: {exc}")
    finally:
        cli.cerrar()


if __name__ == "__main__":
    main()
