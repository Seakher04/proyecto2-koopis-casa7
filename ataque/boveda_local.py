"""
boveda_local.py - Boveda de prueba (mock) de la Casa 5 para ensayar los ataques en local.

Reusa el MISMO protocolo que casa5.py (framing, DH, derivacion, AES-CBC + HMAC) con la
config por defecto, asi recon.py la calibra sola y los ataques corren sin cambios.

Trae interruptores de defensa para ver cada ataque funcionando y, con la defensa puesta,
fallando (el contraste para el informe):
    valida_a     el handshake valida 2 <= A <= P-2  (frena el ataque de clave invalida)
    revisa_seq   descarta mensajes con SEQ repetido  (frena el replay)
    revisa_hmac  verifica el HMAC antes de descifrar  (frena la manipulacion)
    revisa_token exige el token de sesion en cada comando  (frena los comandos sin sesion)
    revisa_rol   el invitado (hacinado) solo puede consultar  (frena escribir sin permiso)
Por defecto las defensas estan en el estado VULNERABLE para el ataque que corresponde
(valida_a y revisa_seq apagadas; revisa_hmac, revisa_token y revisa_rol encendidas).

Uso:
    python boveda_local.py [puerto] [palabras...]
      palabras: seguro      -> enciende todas las defensas
                valida_a    -> solo valida A
                revisa_seq  -> solo anti-replay
                sin_hmac    -> apaga la verificacion del HMAC (integridad rota)
                sin_token   -> no valida el token de sesion
                sin_roles   -> el invitado puede escribir (sin autorizacion por rol)
Correr con `python` (no `python -I`): usa casa5, que usa la libreria cryptography.
"""

import hashlib
import hmac
import json
import secrets
import socket
import sys
import threading

import casa5
from casa5 import CONFIG, P, G

HOST = "127.0.0.1"


class Defensas:
    """Que protecciones tiene encendidas este servidor."""
    def __init__(self, valida_a=False, revisa_seq=False, revisa_hmac=True,
                 revisa_token=True, revisa_rol=True):
        self.valida_a = valida_a
        self.revisa_seq = revisa_seq
        self.revisa_hmac = revisa_hmac
        self.revisa_token = revisa_token
        self.revisa_rol = revisa_rol

    def __str__(self):
        return (f"valida_a={self.valida_a} revisa_seq={self.revisa_seq} "
                f"revisa_hmac={self.revisa_hmac} revisa_token={self.revisa_token} "
                f"revisa_rol={self.revisa_rol}")


def _mk(clave, perfil):
    """Registro de usuario: salt aleatorio + sha256(salt + clave)."""
    salt = secrets.token_bytes(8)
    return (salt.hex(), hashlib.sha256(salt + clave.encode()).hexdigest(), perfil)


USUARIOS = {
    "ratonton": _mk("ratoncinado", "hacinado"),   # invitado, publico en el PDF
    "meli": _mk("clavejefe", "jefe"),
}

# El invitado (hacinado) solo lee; escribir (ADD/DEL) es de jefe o integrante.
PERFILES_ESCRITURA = {"jefe", "integrante"}

# Plantilla de la boveda. Cada servidor arranca con su propia copia.
VAULT_BASE = {
    "mensaje": "si lees esto, el handshake no valido el valor A",
    "pin_jefe": "4821",
}
LOCK = threading.Lock()


def _leer_A(payload):
    # Mismo formato que manda el cliente (CONFIG.HS_FORMAT): raw = 256 bytes big-endian.
    if CONFIG.HS_FORMAT == "raw":
        return int.from_bytes(payload, "big")
    return int(json.loads(payload.decode())[CONFIG.HS_FIELD_A], 16)


def _payload_B(B):
    if CONFIG.HS_FORMAT == "raw":
        return B.to_bytes(casa5.LARGO_DH, "big")
    return json.dumps({CONFIG.HS_FIELD_B: format(B, "x")}).encode()


def atender(conn, d, vault):
    """Atiende a un custodio con las defensas 'd' sobre su boveda 'vault'."""
    try:
        tipo, payload = casa5.recibir_frame(conn)
        if tipo != casa5.HELLO:
            return
        A = _leer_A(payload)
        if d.valida_a and not (2 <= A <= P - 2):
            conn.sendall(casa5.construir_frame(casa5.ERR_MSG, b""))
            return
        b = secrets.randbelow(P - 3) + 2
        B = pow(G, b, P)
        K = pow(A, b, P)                       # usa el A recibido (vulnerable si no se valida)
        conn.sendall(casa5.construir_frame(casa5.HELLO_ACK, _payload_B(B)))
        enc_c2s, mac_c2s, enc_s2c, mac_s2c = casa5.derivar_claves(K)

        def abrir(tipo, payload):
            iv, ct, tag = payload[:16], payload[16:-32], payload[-32:]
            if d.revisa_hmac:
                if not hmac.compare_digest(casa5.calcular_hmac(mac_c2s, tipo, iv, ct), tag):
                    return None
            try:
                return json.loads(casa5.aes_cbc_descifrar(enc_c2s, iv, ct).decode())
            except Exception:
                return None

        def enviar(tipo, dic):
            iv = secrets.token_bytes(16)
            ct = casa5.aes_cbc_cifrar(enc_s2c, iv, json.dumps(dic).encode())
            tag = casa5.calcular_hmac(mac_s2c, tipo, iv, ct)
            conn.sendall(casa5.construir_frame(tipo, iv + ct + tag))

        token = None
        perfil = None
        ultimo_seq = -1
        while True:
            try:
                tipo, payload = casa5.recibir_frame(conn)
            except casa5.ErrorCasa5:
                return
            datos = abrir(tipo, payload)
            if datos is None:          # HMAC malo o descifrado roto: cerramos
                return

            seq = datos.get(CONFIG.F_SEQ)
            if d.revisa_seq and seq is not None:
                if seq <= ultimo_seq:
                    enviar(casa5.ERR_SESION, {"error": "seq repetido"})   # frena el replay
                    continue
                ultimo_seq = seq

            if tipo == casa5.LOGIN:
                u = datos.get(CONFIG.F_USER)
                p = datos.get(CONFIG.F_PASS)
                reg = USUARIOS.get(u)
                ok = bool(reg) and hashlib.sha256(
                    bytes.fromhex(reg[0]) + str(p).encode()).hexdigest() == reg[1]
                if ok:
                    token = secrets.token_hex(16)
                    perfil = reg[2]
                    enviar(casa5.LOGIN_OK, {CONFIG.F_TOKEN: token})
                else:
                    enviar(casa5.LOGIN_FAIL, {})

            elif tipo in (casa5.CMD_ASK, casa5.CMD_ADD, casa5.CMD_DEL):
                if d.revisa_token and (not token or datos.get(CONFIG.F_TOKEN) != token):
                    enviar(casa5.ERR_SESION, {})
                    continue
                # Autorizacion por rol: escribir (ADD/DEL) es solo de jefe/integrante.
                if (tipo in (casa5.CMD_ADD, casa5.CMD_DEL) and d.revisa_rol
                        and perfil not in PERFILES_ESCRITURA):
                    enviar(casa5.ERR_ALLOW, {})
                    continue
                clave = datos.get(CONFIG.F_KEY, "")
                if tipo == casa5.CMD_ASK:
                    with LOCK:
                        if clave == "" or clave == 0:   # "" (mock) o pagina=0 (Casa 5 real): vuelca todo
                            enviar(casa5.RET_OK, {CONFIG.F_VALUE: dict(vault)})
                        elif clave in vault:
                            enviar(casa5.RET_OK, {CONFIG.F_VALUE: vault[clave]})
                        else:
                            enviar(casa5.RET_UNKN, {})
                elif tipo == casa5.CMD_ADD:
                    with LOCK:
                        if clave in vault:
                            enviar(casa5.RET_EXIST, {})
                        else:
                            vault[clave] = datos.get(CONFIG.F_VALUE)
                            enviar(casa5.RET_OK, {})
                else:  # CMD_DEL
                    with LOCK:
                        if clave in vault:
                            del vault[clave]
                            enviar(casa5.RET_OK, {})
                        else:
                            enviar(casa5.RET_UNKN, {})

            elif tipo == casa5.CMD_END:
                enviar(casa5.RET_OK, {})
                return
            else:
                enviar(casa5.ERR_TYPE, {})
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def servir(puerto, defensas=None, listo=None):
    """Abre el socket y atiende a cada custodio en su propio hilo."""
    d = defensas or Defensas()
    vault = dict(VAULT_BASE)                  # cada servidor arranca con su propia copia
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, puerto))
    s.listen(50)
    if listo is not None:
        listo.set()
    print(f"[boveda] escuchando en {HOST}:{puerto}  ({d})")
    while True:
        conn, _ = s.accept()
        threading.Thread(target=atender, args=(conn, d, vault), daemon=True).start()


def main():
    puerto = 6005
    d = Defensas()
    for a in sys.argv[1:]:
        low = a.lower()
        if a.isdigit():
            puerto = int(a)
        elif low == "seguro":
            d = Defensas(valida_a=True, revisa_seq=True, revisa_hmac=True)
        elif low == "valida_a":
            d.valida_a = True
        elif low == "revisa_seq":
            d.revisa_seq = True
        elif low == "sin_hmac":
            d.revisa_hmac = False
        elif low == "sin_token":
            d.revisa_token = False
        elif low == "sin_roles":
            d.revisa_rol = False
    servir(puerto, d)


if __name__ == "__main__":
    main()
