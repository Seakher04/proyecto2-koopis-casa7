"""
manipular.py - Sonda de integridad (cobertura del HMAC) contra la Boveda de la Casa 5.

Arma un CMD_ASK valido y lo reenvia con un bit volteado, por separado, en:
    - el byte de tipo del frame
    - el IV
    - el ciphertext
    - el tag (el HMAC mismo)
Si el servidor RESPONDE en vez de cortar, ese campo no esta protegido por la verificacion
de integridad. Un servidor correcto corta ante cualquiera de las cuatro. El caso clave es
el tag: si una copia con el tag corrupto se acepta, el servidor no verifica el HMAC.

Cada prueba usa una conexion nueva (al romper el HMAC el servidor cierra). Antes de
correr: calibrar con recon.py y pegar el CONFIG en casa5.py.
Correr con `python manipular.py <IP> [puerto]`  (no `python -I`).
"""

import sys

import casa5
from casa5 import CONFIG

USUARIO = "ratonton"
CLAVE = "ratoncinado"


def _frame_valido(c):
    """Un CMD_ASK sellado con el seq/token de esta sesion."""
    cuerpo = {CONFIG.F_KEY: "", CONFIG.F_SEQ: c.seq, CONFIG.F_TOKEN: c.token}
    return c._sellar(casa5.CMD_ASK, cuerpo)


def _una_prueba(host, puerto, etiqueta, mutar):
    """Login + un envio manipulado. Devuelve True si el servidor lo ACEPTO (campo no protegido)."""
    try:
        with casa5.ClienteCasa5(host, puerto) as c:
            c.handshake()
            t, _, _ = c.login(USUARIO, CLAVE)
            if t != casa5.LOGIN_OK:
                print(f"  {etiqueta:18}: login fallo ({casa5.nombre(t)})")
                return None
            tipo_frame, payload = mutar(casa5.CMD_ASK, bytearray(_frame_valido(c)))
            c.enviar(tipo_frame, bytes(payload))
            t2, m2, _ = c.recibir_cifrado()
            print(f"  {etiqueta:18}: el servidor RESPONDIO {casa5.nombre(t2)} (mac_ok={m2})  -> NO protegido")
            return True
    except casa5.ErrorCasa5:
        print(f"  {etiqueta:18}: el servidor corto  -> protegido")
        return False
    except Exception as e:
        print(f"  {etiqueta:18}: corto/error ({type(e).__name__})  -> protegido")
        return False


# --- mutadores: devuelven (tipo_de_frame, payload) ---
def _flip_tipo(tipo, p):
    return (0x2F, p)                 # tipo distinto (CMD desconocido) con el mismo payload y tag

def _flip_iv(tipo, p):
    p[0] ^= 0x01                     # voltea un bit del IV
    return (tipo, p)

def _flip_ct(tipo, p):
    p[16] ^= 0x01                    # voltea un bit del ciphertext
    return (tipo, p)

def _flip_tag(tipo, p):
    p[-1] ^= 0x01                    # voltea un bit del tag (el HMAC)
    return (tipo, p)


def correr(host, puerto):
    tipo_ok = _una_prueba(host, puerto, "tipo volteado", _flip_tipo)
    _una_prueba(host, puerto, "IV volteado", _flip_iv)
    _una_prueba(host, puerto, "ciphertext volteado", _flip_ct)
    tag_ok = _una_prueba(host, puerto, "tag volteado", _flip_tag)

    print("  ----")
    if tag_ok:
        print("  >> VULNERABLE: acepto una copia con el tag corrupto. No verifica el HMAC.")
    elif tipo_ok:
        print("  >> VULNERABLE: el byte de tipo no esta autenticado (se puede cambiar la operacion).")
    else:
        print("  >> PROTEGIDO: rechazo todas las manipulaciones.")


def main():
    if len(sys.argv) < 2:
        print("Uso: python manipular.py <IP> [puerto]")
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Sonda de integridad contra {host}:{puerto} (Casa 5) ===")
    correr(host, puerto)


if __name__ == "__main__":
    main()
