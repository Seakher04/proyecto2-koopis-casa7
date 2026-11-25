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
            raw_ack = c.hello_ack_raw or b""
            c.cerrar()
            if ok:
                aviso = ""
                if formato == "raw" and len(raw_ack) != casa5.LARGO_DH:
                    aviso = f" [OJO: len(HELLO_ACK)={len(raw_ack)}, esperado {casa5.LARGO_DH}]"
                print(
                    f"[HELLO] formato detectado: {formato!r} "
                    f"(len={len(raw_ack)}, prefijo={raw_ack[:12].hex()}){aviso}"
                )
                return True
        except Exception as e:
            print(f"[HELLO] {formato!r} no sirve ({type(e).__name__}: {e})")
    print("[HELLO] no se detecto el formato. Capturar con Wireshark que manda el servidor.")
    return False


# ---------------------------------------------------------------------------
# Paso 2: esquema de derivacion de claves
# ---------------------------------------------------------------------------

ESQUEMAS_K = [256, "sha256", "min", "hex"]
ESQUEMAS_ORDEN = ["k_label_dir", "k_dir_label", "k_label", "label_dir_k", "dir_label_k"]
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
ESQUEMAS_HMAC = ["type_iv_ct", "iv_ct", "ct"]
ESQUEMAS_LAYOUT = ["iv_ct_mac", "iv_mac_ct", "mac_iv_ct"]


def _generar_esquemas():
    """Genera combinaciones sin redundancias, priorizando layout iv_ct_mac."""
    combos = []
    vistos = set()
    for layout in ESQUEMAS_LAYOUT:
        for k_bytes in ESQUEMAS_K:
            for orden in ESQUEMAS_ORDEN:
                dirs = [(b"", b"")] if orden == "k_label" else ESQUEMAS_DIR
                for label, dir_par, hmac_in in itertools.product(ESQUEMAS_LABEL, dirs, ESQUEMAS_HMAC):
                    esq = (k_bytes, orden, label, dir_par, hmac_in, layout)
                    if esq not in vistos:
                        vistos.add(esq)
                        combos.append(esq)
    return combos


def _aplicar(esq):
    (CONFIG.K_BYTES, CONFIG.DERIV_ORDER, (CONFIG.LABEL_ENC, CONFIG.LABEL_MAC),
     (CONFIG.DIR_C2S, CONFIG.DIR_S2C), CONFIG.HMAC_INPUT, CONFIG.LAYOUT) = esq


def _probar_login(host, puerto, timeout=1.5):
    """Un handshake real + un LOGIN de prueba. Devuelve ((tipo, mac_ok, datos, raw), estado)."""
    try:
        c = _conectar(host, puerto)
        c.handshake()
        c.enviar_cifrado(casa5.LOGIN, {CONFIG.F_USER: USUARIO, CONFIG.F_PASS: CLAVE})
        c.sock.settimeout(timeout)
        tipo, payload = c.recibir()
        c.cerrar()
        if tipo in (casa5.HELLO, casa5.HELLO_ACK):
            return (tipo, None, None, payload), "ok"
        mac_ok, datos = c._abrir(tipo, payload)
        return (tipo, mac_ok, datos, payload), "ok"
    except TimeoutError:
        return None, "timeout"
    except casa5.ErrorCasa5 as e:
        return None, f"cerrado ({e})"
    except Exception as e:
        return None, f"error ({type(e).__name__}: {e})"


def detectar_claves(host, puerto):
    combos = _generar_esquemas()
    print(f"[CLAVES] probando hasta {len(combos)} esquemas de derivacion...")
    parcial = None
    conteos = {}
    vistas_sin_mac = set()
    for i, esq in enumerate(combos, 1):
        _aplicar(esq)
        r, estado = _probar_login(host, puerto)
        conteos[estado] = conteos.get(estado, 0) + 1
        if r is None:
            if i == 1 and estado == "timeout":
                print("[CLAVES] aviso: el servidor no responde al LOGIN (timeout); las pruebas pueden tardar.")
            continue
        tipo, mac_ok, datos, raw = r
        etiqueta = (
            f"K={esq[0]} orden={esq[1]} label={esq[2]} dir={esq[3]} "
            f"hmac={esq[4]} layout={esq[5]}"
        )
        if mac_ok or datos is not None:
            print(f"[CLAVES] candidato ({casa5.nombre(tipo)}) -> {etiqueta}")
            if tipo in (casa5.LOGIN_OK, casa5.LOGIN_FAIL):
                print("[CLAVES] CONFIRMADO: el servidor proceso el LOGIN con estas claves.")
                return esq
            parcial = parcial or esq  # ERR_MSG: claves ok, pero el esquema JSON falla
        elif tipo not in vistas_sin_mac:
            vistas_sin_mac.add(tipo)
            print(
                f"[CLAVES] respuesta sin descifrar/sin HMAC valido: "
                f"tipo={casa5.nombre(tipo)} len={len(raw)} hex={raw[:32].hex()}"
            )
        if i % 60 == 0:
            print(f"   ...{i}/{len(combos)}")
    if parcial:
        _aplicar(parcial)
        print("[CLAVES] claves validas, pero el LOGIN dio error. Revisar nombres de campos JSON.")
        return parcial
    print(f"[CLAVES] ningun esquema funciono. Resumen de respuestas: {conteos}")
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
    print(f"[SESION] handshake ok, K (primeros 16 hex) = {casa5._serializar_k(c.K, CONFIG.K_BYTES)[:8].hex()}")
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
              "DIR_C2S", "DIR_S2C", "HMAC_INPUT", "LAYOUT", "F_USER", "F_PASS"):
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
    r, _ = _probar_login(host, puerto)
    if not (r and r[0] in (casa5.LOGIN_OK, casa5.LOGIN_FAIL)):
        detectar_campos_login(host, puerto)

    imprimir_config()
    sesion_de_prueba(host, puerto)


if __name__ == "__main__":
    main()
