"""
fuente.py - Prueba si la Casa 5 deriva las claves de un valor OBSERVABLE (B, A, ...) en
vez del secreto compartido K.

Pista de la Casa 5: "observen de que depende el valor de la clave/token entre una
conexion y otra". La clave DEBERIA depender de K (el secreto, que nadie ve). Pero entre
conexiones lo que cambia y ademas viaja en claro es B (el valor publico del servidor).
Si la boveda derivo la clave de B (o de A, o de una combinacion) en vez de K, cualquiera
que lea B puede calcular la clave, y por eso recon (que deriva de K) nunca calzo.

Este script prueba cada fuente contra la misma grilla de esquemas de recon. Si alguna
logra que el servidor procese el LOGIN (no cierra), encontro la derivacion.

Uso:
    python fuente.py <IP> [puerto] [fuente]
      fuente: B (por defecto), A, A+B, A*B, B-A, K (control)
Correr con `python` (no `python -I`).
"""

import secrets
import sys

import casa5
import recon
from casa5 import CONFIG, P, G

USUARIO = recon.USUARIO
CLAVE = recon.CLAVE

FUENTES = {
    "B": lambda A, B, K: B,
    "A": lambda A, B, K: A,
    "A+B": lambda A, B, K: (A + B) % P,
    "A*B": lambda A, B, K: (A * B) % P,
    "B-A": lambda A, B, K: (B - A) % P,
    "K": lambda A, B, K: K,            # control: deberia fallar igual que recon
}


def _probar(host, puerto, fuente_fn, timeout=2.0):
    """Un handshake + LOGIN derivando la clave de la fuente. Devuelve (tipo, mac_ok) o None."""
    try:
        c = casa5.ClienteCasa5(host, puerto, timeout)
        c.conectar()
        a = secrets.randbelow(P - 3) + 2
        A = pow(G, a, P)
        c.enviar(casa5.HELLO, c._payload_hello(A))
        tipo, payload = c.recibir()
        if tipo != casa5.HELLO_ACK:
            c.cerrar()
            return None
        B = c._leer_B(payload)
        K = pow(B, a, P)
        S = fuente_fn(A, B, K)
        c.enc_c2s, c.mac_c2s, c.enc_s2c, c.mac_s2c = casa5.derivar_claves(S)
        c.enviar_cifrado(casa5.LOGIN, {CONFIG.F_USER: USUARIO, CONFIG.F_PASS: CLAVE})
        c.sock.settimeout(timeout)
        tipo2, payload2 = c.recibir()
        mac_ok, _ = c._abrir(tipo2, payload2)
        c.cerrar()
        return (tipo2, mac_ok)
    except Exception:
        return None


def _dump_boveda(host, puerto, fuente_fn):
    """Con la fuente y el esquema ya encontrados, hace login de invitado y lee la boveda."""
    try:
        c = casa5.ClienteCasa5(host, puerto, 3.0)
        c.conectar()
        a = secrets.randbelow(P - 3) + 2
        A = pow(G, a, P)
        c.enviar(casa5.HELLO, c._payload_hello(A))
        tipo, payload = c.recibir()
        if tipo != casa5.HELLO_ACK:
            c.cerrar()
            return
        B = c._leer_B(payload)
        K = pow(B, a, P)
        c.enc_c2s, c.mac_c2s, c.enc_s2c, c.mac_s2c = casa5.derivar_claves(fuente_fn(A, B, K))
        tipo, mac_ok, datos = c.login(USUARIO, CLAVE)
        print(f"  LOGIN -> {casa5.nombre(tipo)}  mac_ok={mac_ok}  datos={datos}")
        if tipo == casa5.LOGIN_OK:
            tipo, mac_ok, datos = c.comando(casa5.CMD_ASK, **{CONFIG.F_KEY: ""})
            print(f"  CMD_ASK('') -> {casa5.nombre(tipo)}  datos={datos}")
        c.cerrar()
    except Exception as e:
        print(f"  (no se completo la sesion: {type(e).__name__})")


def correr(host, puerto, nombre):
    fuente_fn = FUENTES[nombre]
    combos = recon._generar_esquemas()
    print(f"[FUENTE={nombre}] probando {len(combos)} esquemas derivando la clave de '{nombre}'...")
    for i, esq in enumerate(combos, 1):
        recon._aplicar(esq)
        r = _probar(host, puerto, fuente_fn)
        if r is not None:
            tipo, mac_ok = r
            if mac_ok or tipo in (casa5.LOGIN_OK, casa5.LOGIN_FAIL):
                print(f"\n[FUENTE] *** ENTRO *** la clave se deriva de '{nombre}'")
                print(f"  respuesta del servidor: {casa5.nombre(tipo)}  mac_ok={mac_ok}")
                print(f"  esquema: K_BYTES={esq[0]} orden={esq[1]} label={esq[2]} "
                      f"dir={esq[3]} hmac={esq[4]} layout={esq[5]}")
                print("  intentando leer la boveda...")
                _dump_boveda(host, puerto, fuente_fn)
                return (nombre, esq)
        if i % 300 == 0:
            print(f"   ...{i}/{len(combos)}")
    print(f"[FUENTE={nombre}] nada, el servidor cerro en todos.")
    return None


def main():
    if len(sys.argv) < 2:
        print("Uso: python fuente.py <IP> [puerto] [fuente: B|A|A+B|A*B|B-A|K]")
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    nombre = sys.argv[3] if len(sys.argv) > 3 else "B"
    if nombre not in FUENTES:
        print(f"fuente desconocida: {nombre}. Opciones: {', '.join(FUENTES)}")
        return
    print(f"=== Probando fuente de la clave contra {host}:{puerto} (Casa 5) ===")
    recon.detectar_hello(host, puerto)   # fija HS_FORMAT (raw en la Casa 5 real)
    correr(host, puerto, nombre)


if __name__ == "__main__":
    main()
