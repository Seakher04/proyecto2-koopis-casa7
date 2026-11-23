"""
recon.py - Reconocimiento y calibracion contra la Boveda de Casa 5.

El enunciado no fija algunos bytes (formato del HELLO, serializacion de K, etiquetas,
direcciones, entrada del HMAC, nombres de los campos JSON). Este script los descubre
solo: hace handshakes reales y prueba combinaciones hasta que el servidor ACEPTA un
LOGIN de invitado. Cuando lo logra imprime el CONFIG ganador para pegarlo en casa5.py,
muestra el token y prueba un CMD_ASK.

Uso:
    python recon.py <IP_de_la_boveda> [puerto]
    (puerto por defecto 6005)

Credenciales de invitado del enunciado: usuario=ratonton clave=ratoncinado (perfil hacinado)
"""

import itertools
import sys

import casa5
from casa5 import CONFIG

USUARIO = "ratonton"
CLAVE = "ratoncinado"


def _conectar(host, puerto):
    c = casa5.ClienteCasa5(host, puerto, timeout=6.0)
    c.conectar()
    return c


# ---------------------------------------------------------------------------
# Paso 1: formato del HELLO (json vs raw)
# ---------------------------------------------------------------------------

def detectar_hello(host, puerto):
    for formato in ("json", "raw"):
        CONFIG.HS_FORMAT = formato
        try:
            c = _conectar(host, puerto)
            c.handshake()  # si B se parsea a un entero DH valido, este formato sirve
            ok = 2 <= c.K <= casa5.P - 2
            c.cerrar()
            if ok:
                print(f"[HELLO] formato detectado: {formato!r}")
                return True
        except Exception as e:
            print(f"[HELLO] {formato!r} no sirve ({type(e).__name__}: {e})")
    print("[HELLO] no se detecto el formato. Capturar con Wireshark que manda el servidor.")
    return False


# ---------------------------------------------------------------------------
# Paso 2: esquema de derivacion de claves
# ---------------------------------------------------------------------------

ESQUEMAS_K = [256, 32]
ESQUEMAS_ORDEN = ["k_label_dir", "k_dir_label", "k_label"]
ESQUEMAS_LABEL = [
    (b"ENC", b"MAC"),
    (b"enc", b"mac"),
    (b"cifrado", b"integridad"),   # convencion vista en el curso
    (b"ENC", b"mac"),
]
ESQUEMAS_DIR = [
    (b"Cliente->Servidor", b"Servidor->Cliente"),
    (b"cliente", b"servidor"),
    (b"C2S", b"S2C"),
    (b"", b""),                    # por si no usan direccion
]
ESQUEMAS_HMAC = ["type_iv_ct", "iv_ct"]


def _aplicar(esq):
    (CONFIG.K_BYTES, CONFIG.DERIV_ORDER, (CONFIG.LABEL_ENC, CONFIG.LABEL_MAC),
     (CONFIG.DIR_C2S, CONFIG.DIR_S2C), CONFIG.HMAC_INPUT) = esq


def _probar_login(host, puerto):
    """Un handshake real + un LOGIN de prueba. Devuelve (tipo, mac_ok, datos) o None si cerro."""
    try:
        c = _conectar(host, puerto)
        c.handshake()
        c.enviar_cifrado(casa5.LOGIN, {CONFIG.F_USER: USUARIO, CONFIG.F_PASS: CLAVE})
        c.sock.settimeout(4.0)
        r = c.recibir_cifrado()
        c.cerrar()
        return r
    except Exception:
        return None


def detectar_claves(host, puerto):
    combos = list(itertools.product(
        ESQUEMAS_K, ESQUEMAS_ORDEN, ESQUEMAS_LABEL, ESQUEMAS_DIR, ESQUEMAS_HMAC))
    print(f"[CLAVES] probando hasta {len(combos)} esquemas de derivacion...")
    parcial = None
    for i, esq in enumerate(combos, 1):
        _aplicar(esq)
        r = _probar_login(host, puerto)
        if r is None:
            continue  # el servidor cerro: nuestro HMAC no calzo, esquema incorrecto
        tipo, mac_ok, datos = r
        etiqueta = (f"K={esq[0]} orden={esq[1]} label={esq[2]} dir={esq[3]} hmac={esq[4]}")
        if mac_ok or datos is not None:
            print(f"[CLAVES] candidato ({casa5.nombre(tipo)}) -> {etiqueta}")
            if tipo in (casa5.LOGIN_OK, casa5.LOGIN_FAIL):
                print("[CLAVES] CONFIRMADO: el servidor proceso el LOGIN con estas claves.")
                return esq
            parcial = parcial or esq  # ERR_MSG: claves ok, pero el esquema JSON falla
        if i % 24 == 0:
            print(f"   ...{i}/{len(combos)}")
    if parcial:
        _aplicar(parcial)
        print("[CLAVES] claves validas, pero el LOGIN dio error. Revisar nombres de campos JSON.")
        return parcial
    print("[CLAVES] ningun esquema funciono. El servidor valida distinto o cierra siempre.")
    return None


# ---------------------------------------------------------------------------
# Paso 3: nombres de los campos del LOGIN (si el paso 2 quedo en 'parcial')
# ---------------------------------------------------------------------------

ESQUEMAS_CAMPOS = [
    ("usuario", "clave"),
    ("user", "pass"),
    ("usuario", "contrasena"),
    ("usuario", "password"),
    ("nombre", "clave"),
    ("usuario", "contrasenia"),
]


def detectar_campos_login(host, puerto):
    print("[CAMPOS] probando nombres de campos del LOGIN...")
    for fu, fp in ESQUEMAS_CAMPOS:
        CONFIG.F_USER, CONFIG.F_PASS = fu, fp
        for con_seq in (True, False):
            try:
                c = _conectar(host, puerto)
                c.handshake()
                cuerpo = {fu: USUARIO, fp: CLAVE}
                if con_seq:
                    cuerpo[CONFIG.F_SEQ] = 0
                c.enviar(casa5.LOGIN, c._sellar(casa5.LOGIN, cuerpo))
                c.sock.settimeout(4.0)
                tipo, mac_ok, datos = c.recibir_cifrado()
                c.cerrar()
                if tipo in (casa5.LOGIN_OK, casa5.LOGIN_FAIL):
                    print(f"[CAMPOS] LOGIN aceptado: user={fu!r} pass={fp!r} seq_incluido={con_seq}")
                    return True
            except Exception:
                pass
    print("[CAMPOS] no se hallaron los nombres. Ver el enunciado/codigo de Casa 5 o capturar trafico.")
    return False


# ---------------------------------------------------------------------------
# Paso 4: login real de invitado + dump de token + un comando
# ---------------------------------------------------------------------------

def sesion_de_prueba(host, puerto):
    c = _conectar(host, puerto)
    c.handshake()
    print(f"[SESION] handshake ok, K (primeros 16 hex) = {c.K.to_bytes(CONFIG.K_BYTES,'big')[:8].hex()}")
    tipo, mac_ok, datos = c.login(USUARIO, CLAVE)
    print(f"[SESION] LOGIN -> {casa5.nombre(tipo)}  mac_ok={mac_ok}")
    print(f"[SESION] respuesta completa del servidor: {datos}")
    print(f"[SESION] token guardado: {c.token!r}")
    if tipo == casa5.LOGIN_OK:
        tipo, mac_ok, datos = c.comando(casa5.CMD_ASK, **{CONFIG.F_KEY: ""})
        print(f"[SESION] CMD_ASK(clave='') -> {casa5.nombre(tipo)}  datos={datos}")
    c.cerrar()


def imprimir_config():
    print("\n==================== CONFIG GANADOR ====================")
    for k in ("HS_FORMAT", "K_BYTES", "DERIV_ORDER", "LABEL_ENC", "LABEL_MAC",
              "DIR_C2S", "DIR_S2C", "HMAC_INPUT", "F_USER", "F_PASS"):
        print(f"    CONFIG.{k} = {getattr(CONFIG, k)!r}")
    print("=======================================================\n")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Recon contra {host}:{puerto} ===")

    if not detectar_hello(host, puerto):
        return
    esq = detectar_claves(host, puerto)
    if esq is None:
        return
    # Si el LOGIN no fue aceptado aun, calibrar los nombres de los campos.
    r = _probar_login(host, puerto)
    if not (r and r[0] in (casa5.LOGIN_OK, casa5.LOGIN_FAIL)):
        detectar_campos_login(host, puerto)

    imprimir_config()
    sesion_de_prueba(host, puerto)


if __name__ == "__main__":
    main()
