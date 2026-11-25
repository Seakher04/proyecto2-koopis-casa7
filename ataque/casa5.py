"""
casa5.py - Cliente base para el protocolo "La ratonera" (Casa 5, Proyecto 2 de Redes).

Habla el formato de Casa 5:
    <Length (4B, big-endian)><Type (1B)><Payload (Length-1 bytes)>

Handshake Diffie-Hellman clasico (RFC 3526 grupo 14), derivacion de claves con SHA-256
y payload cifrado con AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).

OJO: el enunciado de Casa 5 deja sin fijar varios detalles de bytes. Todos viven en el
bloque CONFIG. recon.py los detecta solos contra el servidor vivo. Si algo no calza el
miercoles, se ajusta aqui en un unico lugar y todos los ataques se arreglan de una vez.

Correr con `python` (no `python -I`): usa la libreria cryptography del proyecto.
"""

import hashlib
import hmac
import json
import secrets
import socket
import struct

from cryptography.hazmat.primitives import padding as _pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --- Parametros Diffie-Hellman: RFC 3526 grupo 14, primo de 2048 bits, generador 2 ---
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
LARGO_DH = 256  # A y B viajan como enteros de 256 bytes big-endian


# --- Tipos de mensaje (tabla seccion 4 del protocolo de Casa 5) ---
HELLO = 0x01
HELLO_ACK = 0x02
LOGIN = 0x10
LOGIN_OK = 0x11
LOGIN_FAIL = 0x12
CMD_ASK = 0x20
CMD_ADD = 0x21
CMD_DEL = 0x22
CMD_END = 0x23
RET_OK = 0x30
RET_UNKN = 0x31
RET_EXIST = 0x32
ERR_TYPE = 0xF0
ERR_MSG = 0xF1
ERR_LEN = 0xF2
ERR_SESION = 0xF3
ERR_ALLOW = 0xF4
ERR_SERV = 0xF5

NOMBRE_TIPO = {
    0x01: "HELLO", 0x02: "HELLO_ACK", 0x10: "LOGIN", 0x11: "LOGIN_OK",
    0x12: "LOGIN_FAIL", 0x20: "CMD_ASK", 0x21: "CMD_ADD", 0x22: "CMD_DEL",
    0x23: "CMD_END", 0x30: "RET_OK", 0x31: "RET_UNKN", 0x32: "RET_EXIST",
    0xF0: "ERR_TYPE", 0xF1: "ERR_MSG", 0xF2: "ERR_LEN", 0xF3: "ERR_SESION",
    0xF4: "ERR_ALLOW", 0xF5: "ERR_SERV",
}


def nombre(tipo):
    return NOMBRE_TIPO.get(tipo, f"0x{tipo:02X}")


class CONFIG:
    """Los detalles que el enunciado NO fija. recon.py los ajusta; aqui estan los valores
    de arranque mas probables segun el enunciado y las convenciones del curso."""

    # Valores EXACTOS de la Casa 5 (leidos de su codigo: core/handshake.py,
    # core/derivacion.py, core/integridad.py, cliente.py).

    # HELLO: A y B viajan como enteros de 256 bytes big-endian (raw).
    HS_FORMAT = "raw"
    HS_FIELD_A = "A"
    HS_FIELD_B = "B"

    # Derivacion: sha256(ETIQUETA + K.to_bytes(256)). La etiqueta va pegada a la
    # direccion con guion ("ENC-CS", "MAC-SC", ...) y ANTES de K.
    K_BYTES = 256
    LABEL_ENC = b"ENC-"
    LABEL_MAC = b"MAC-"
    DIR_C2S = b"CS"
    DIR_S2C = b"SC"
    DERIV_ORDER = "label_dir_k"   # etiqueta + direccion + K

    # Payload cifrado: IV(16) || ciphertext || HMAC(32).
    LAYOUT = "iv_ct_mac"
    # Que entra al HMAC: el byte de tipo, el IV y el ciphertext.
    HMAC_INPUT = "type_iv_ct"

    # Nombres de los campos del JSON (del codigo de la Casa 5).
    F_USER = "usuario"
    F_PASS = "contrasena"
    F_TOKEN = "token"
    F_SEQ = "seq"
    F_KEY = "pagina"   # CMD_ASK usa {"pagina": N}; CMD_ADD usa "dato", CMD_DEL "id_dato"
    F_VALUE = "dato"


class ErrorCasa5(Exception):
    pass


# ---------------------------------------------------------------------------
# Framing <Length><Type><Payload>
# ---------------------------------------------------------------------------

def construir_frame(tipo, payload):
    """Arma un frame. Length = 1 (tipo) + len(payload), uint32 big-endian."""
    longitud = 1 + len(payload)
    return struct.pack("!I", longitud) + struct.pack("!B", tipo) + payload


def _recv_exacto(sock, n):
    partes = []
    faltan = n
    while faltan > 0:
        bloque = sock.recv(faltan)
        if not bloque:
            raise ErrorCasa5("La conexion se cerro antes de completar el frame")
        partes.append(bloque)
        faltan -= len(bloque)
    return b"".join(partes)


def recibir_frame(sock):
    """Lee un frame completo. Devuelve (tipo, payload)."""
    cab = _recv_exacto(sock, 4)
    longitud = struct.unpack("!I", cab)[0]
    if longitud < 1:
        raise ErrorCasa5(f"Length invalido: {longitud}")
    cuerpo = _recv_exacto(sock, longitud)  # 1 byte de tipo + (longitud-1) de payload
    tipo = cuerpo[0]
    payload = cuerpo[1:]
    return tipo, payload


# ---------------------------------------------------------------------------
# Derivacion de claves
# ---------------------------------------------------------------------------

def _concat(kb, label, direccion, orden):
    if orden == "k_label_dir":
        return kb + label + direccion
    if orden == "k_dir_label":
        return kb + direccion + label
    if orden == "label_dir_k":
        return label + direccion + kb
    if orden == "dir_label_k":
        return direccion + label + kb
    if orden == "k_label":  # sin direccion, por si no la usan
        return kb + label
    return kb + label + direccion


def _serializar_k(K, modo):
    if modo == 256:
        return K.to_bytes(256, "big")
    if modo == 32:
        if K.bit_length() <= 256:
            return K.to_bytes(32, "big")
        return hashlib.sha256(K.to_bytes(256, "big")).digest()
    if modo == "sha256":
        return hashlib.sha256(K.to_bytes(256, "big")).digest()
    if modo == "min":
        return K.to_bytes(max(1, (K.bit_length() + 7) // 8), "big")
    if modo == "hex":
        return format(K, "x").encode("ascii")
    return K.to_bytes(int(modo), "big")


def derivar_claves(K):
    """De K saca 4 claves de 32 bytes: (enc_c2s, mac_c2s, enc_s2c, mac_s2c).
    c2s = lo que el cliente usa para enviar; s2c = lo que usa para leer al servidor."""
    kb = _serializar_k(K, CONFIG.K_BYTES)

    def H(label, direccion):
        return hashlib.sha256(_concat(kb, label, direccion, CONFIG.DERIV_ORDER)).digest()

    enc_c2s = H(CONFIG.LABEL_ENC, CONFIG.DIR_C2S)
    mac_c2s = H(CONFIG.LABEL_MAC, CONFIG.DIR_C2S)
    enc_s2c = H(CONFIG.LABEL_ENC, CONFIG.DIR_S2C)
    mac_s2c = H(CONFIG.LABEL_MAC, CONFIG.DIR_S2C)
    return enc_c2s, mac_c2s, enc_s2c, mac_s2c


# ---------------------------------------------------------------------------
# AES-256-CBC + PKCS7 y HMAC-SHA256
# ---------------------------------------------------------------------------

def aes_cbc_cifrar(clave, iv, texto_plano):
    relleno = _pad.PKCS7(128).padder()
    datos = relleno.update(texto_plano) + relleno.finalize()
    cif = Cipher(algorithms.AES(clave), modes.CBC(iv)).encryptor()
    return cif.update(datos) + cif.finalize()


def aes_cbc_descifrar(clave, iv, ciphertext):
    desc = Cipher(algorithms.AES(clave), modes.CBC(iv)).decryptor()
    datos = desc.update(ciphertext) + desc.finalize()
    quitar = _pad.PKCS7(128).unpadder()
    return quitar.update(datos) + quitar.finalize()


def _entrada_hmac(tipo, iv, ciphertext):
    if CONFIG.HMAC_INPUT == "type_iv_ct":
        return bytes([tipo]) + iv + ciphertext
    if CONFIG.HMAC_INPUT == "iv_ct":
        return iv + ciphertext
    if CONFIG.HMAC_INPUT == "ct":
        return ciphertext
    return bytes([tipo]) + iv + ciphertext


def calcular_hmac(clave_mac, tipo, iv, ciphertext):
    return hmac.new(clave_mac, _entrada_hmac(tipo, iv, ciphertext), hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Cliente de alto nivel
# ---------------------------------------------------------------------------

class ClienteCasa5:
    def __init__(self, host, puerto=6005, timeout=10.0):
        self.host = host
        self.puerto = puerto
        self.timeout = timeout
        self.sock = None
        self.enc_c2s = self.mac_c2s = self.enc_s2c = self.mac_s2c = None
        self.seq = 0            # contador anti-repeticion del cliente
        self.token = None       # lo entrega el servidor en LOGIN_OK
        self.K = None           # secreto compartido (para depurar)
        self.hello_ack_raw = None

    # -- conexion --
    def conectar(self):
        self.sock = socket.create_connection((self.host, self.puerto), timeout=self.timeout)

    def cerrar(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        self.conectar()
        return self

    def __exit__(self, *_):
        self.cerrar()

    # -- frames crudos --
    def enviar(self, tipo, payload):
        self.sock.sendall(construir_frame(tipo, payload))

    def recibir(self):
        return recibir_frame(self.sock)

    # -- handshake --
    def _payload_hello(self, A):
        if CONFIG.HS_FORMAT == "raw":
            return A.to_bytes(LARGO_DH, "big")
        return json.dumps({CONFIG.HS_FIELD_A: format(A, "x")}).encode("utf-8")

    def _leer_B(self, payload):
        if CONFIG.HS_FORMAT == "raw":
            return int.from_bytes(payload, "big")
        datos = json.loads(payload.decode("utf-8"))
        return int(datos[CONFIG.HS_FIELD_B], 16)

    def handshake(self, A_forzado=None, K_forzado=None):
        """DH normal, o inyeccion de un A invalido (A_forzado) con su K conocido (K_forzado)."""
        if A_forzado is None:
            a = secrets.randbelow(P - 3) + 2
            A = pow(G, a, P)
        else:
            a, A = None, A_forzado

        self.enviar(HELLO, self._payload_hello(A))
        tipo, payload = self.recibir()
        self.hello_ack_raw = payload
        if tipo != HELLO_ACK:
            raise ErrorCasa5(f"Se esperaba HELLO_ACK, llego {nombre(tipo)}")

        if K_forzado is not None:
            self.K = K_forzado
        else:
            B = self._leer_B(payload)
            self.K = pow(B, a, P)

        self.enc_c2s, self.mac_c2s, self.enc_s2c, self.mac_s2c = derivar_claves(self.K)
        return self.K

    # -- mensajes cifrados --
    def _sellar(self, tipo, dict_json):
        iv = secrets.token_bytes(16)
        ct = aes_cbc_cifrar(self.enc_c2s, iv, json.dumps(dict_json).encode("utf-8"))
        tag = calcular_hmac(self.mac_c2s, tipo, iv, ct)
        if CONFIG.LAYOUT == "mac_iv_ct":
            return tag + iv + ct
        if CONFIG.LAYOUT == "iv_mac_ct":
            return iv + tag + ct
        return iv + ct + tag  # LAYOUT iv_ct_mac

    def _abrir(self, tipo, payload):
        if len(payload) < 48:
            return False, None
        if CONFIG.LAYOUT == "mac_iv_ct":
            tag, iv, ct = payload[:32], payload[32:48], payload[48:]
        elif CONFIG.LAYOUT == "iv_mac_ct":
            iv, tag, ct = payload[:16], payload[16:48], payload[48:]
        else:
            iv, ct, tag = payload[:16], payload[16:-32], payload[-32:]
        esperado = calcular_hmac(self.mac_s2c, tipo, iv, ct)
        mac_ok = hmac.compare_digest(esperado, tag)
        texto = None
        try:
            texto = json.loads(aes_cbc_descifrar(self.enc_s2c, iv, ct).decode("utf-8"))
        except Exception:
            texto = None
        return mac_ok, texto

    def enviar_cifrado(self, tipo, campos):
        """Mete seq (y token si ya hay) en el JSON, cifra y envia."""
        cuerpo = dict(campos)
        cuerpo[CONFIG.F_SEQ] = self.seq
        if self.token is not None and CONFIG.F_TOKEN not in cuerpo:
            cuerpo[CONFIG.F_TOKEN] = self.token
        self.seq += 1
        self.enviar(tipo, self._sellar(tipo, cuerpo))

    def recibir_cifrado(self):
        """Devuelve (tipo, mac_ok, dict_o_None)."""
        tipo, payload = self.recibir()
        if tipo in (HELLO, HELLO_ACK):
            return tipo, None, None
        mac_ok, datos = self._abrir(tipo, payload)
        return tipo, mac_ok, datos

    # -- atajos de sesion --
    def login(self, usuario, clave):
        self.enviar_cifrado(LOGIN, {CONFIG.F_USER: usuario, CONFIG.F_PASS: clave})
        tipo, mac_ok, datos = self.recibir_cifrado()
        if tipo == LOGIN_OK and isinstance(datos, dict):
            # el nombre exacto del campo token puede variar: se toma el primero que parezca
            self.token = datos.get(CONFIG.F_TOKEN) or datos.get("token") or datos.get("sesion")
        return tipo, mac_ok, datos

    def comando(self, tipo_cmd, **campos):
        self.enviar_cifrado(tipo_cmd, campos)
        return self.recibir_cifrado()
