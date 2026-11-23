"""
sesion.py - Sonda de flujo y autenticacion (token) contra la Boveda de la Casa 5.

El protocolo exige el flujo HELLO -> LOGIN -> CMD y que cada comando lleve el token de
sesion que el servidor entrego en LOGIN_OK. Ademas tiene perfiles (jefe/integrante/
hacinado) y el codigo ERR_ALLOW. Esta sonda prueba dos cosas:

  Flujo y token (si de verdad exige una sesion valida):
    1. CMD_ASK sin haber hecho LOGIN.
    2. CMD_ASK con el campo token borrado (tras loguear).
    3. CMD_ASK con un token inventado (tras loguear).
    4. CMD_ASK en una conexion nueva, sin LOGIN, con un token de otra sesion.
  Autorizacion por rol (si el invitado hacinado tiene permisos de mas):
    5. CMD_ADD como invitado  (deberia dar ERR_ALLOW).
    6. CMD_DEL como invitado  (deberia dar ERR_ALLOW).
Si una lectura sin sesion o una escritura de invitado devuelve RET_OK, hay un hueco.

Antes de correr: calibrar con recon.py y pegar el CONFIG en casa5.py.
Correr con `python sesion.py <IP> [puerto]`  (no `python -I`).
"""

import secrets
import sys

import casa5
from casa5 import CONFIG

USUARIO = "ratonton"
CLAVE = "ratoncinado"


def _ask(c, token):
    """Manda un CMD_ASK con el token indicado (None = sin el campo) y devuelve la respuesta."""
    cuerpo = {CONFIG.F_KEY: "", CONFIG.F_SEQ: c.seq}
    if token is not None:
        cuerpo[CONFIG.F_TOKEN] = token
    c.enviar(casa5.CMD_ASK, c._sellar(casa5.CMD_ASK, cuerpo))
    return c.recibir_cifrado()


def _token_real(host, puerto):
    """Consigue un token valido logueandose en una sesion aparte."""
    with casa5.ClienteCasa5(host, puerto) as c:
        c.handshake()
        if c.login(USUARIO, CLAVE)[0] == casa5.LOGIN_OK:
            return c.token
    return None


def _probar(host, puerto, etiqueta, login, token_mode, token_externo=None):
    """Corre un caso y dice si el servidor lo ACEPTO (RET_OK = vulnerable)."""
    try:
        with casa5.ClienteCasa5(host, puerto) as c:
            c.handshake()
            if login and c.login(USUARIO, CLAVE)[0] != casa5.LOGIN_OK:
                print(f"  {etiqueta:40}: no se pudo loguear")
                return False
            if token_mode == "borrado":
                usar = None
            elif token_mode == "inventado":
                usar = secrets.token_hex(16)
            elif token_mode == "externo":
                usar = token_externo
            else:
                usar = c.token
            tipo, _, _ = _ask(c, usar)
            if tipo == casa5.RET_OK:
                print(f"  {etiqueta:40}: RET_OK  -> VULNERABLE (ejecuto sin sesion valida)")
                return True
            print(f"  {etiqueta:40}: {casa5.nombre(tipo)}  -> rechazado")
            return False
    except casa5.ErrorCasa5:
        print(f"  {etiqueta:40}: corto la conexion  -> rechazado")
        return False
    except Exception as e:
        print(f"  {etiqueta:40}: error ({type(e).__name__})  -> rechazado")
        return False


def _escritura(host, puerto, etiqueta, tipo_cmd, campos):
    """Como invitado, intenta una escritura. Devuelve True si el servidor la PERMITE."""
    try:
        with casa5.ClienteCasa5(host, puerto) as c:
            c.handshake()
            if c.login(USUARIO, CLAVE)[0] != casa5.LOGIN_OK:
                print(f"  {etiqueta:40}: no se pudo loguear")
                return False
            tipo, _, _ = c.comando(tipo_cmd, **campos)
            if tipo == casa5.ERR_ALLOW:
                print(f"  {etiqueta:40}: ERR_ALLOW  -> rechazado (bien)")
                return False
            print(f"  {etiqueta:40}: {casa5.nombre(tipo)}  -> VULNERABLE (el invitado escribio)")
            return True
    except casa5.ErrorCasa5:
        print(f"  {etiqueta:40}: corto la conexion  -> rechazado")
        return False
    except Exception as e:
        print(f"  {etiqueta:40}: error ({type(e).__name__})  -> rechazado")
        return False


def correr(host, puerto):
    print("  -- flujo y validacion del token --")
    tok = _token_real(host, puerto)
    r1 = _probar(host, puerto, "CMD_ASK sin LOGIN", login=False, token_mode="borrado")
    r2 = _probar(host, puerto, "CMD_ASK con token borrado", login=True, token_mode="borrado")
    r3 = _probar(host, puerto, "CMD_ASK con token inventado", login=True, token_mode="inventado")
    r4 = _probar(host, puerto, "CMD_ASK con token de otra sesion", login=False,
                 token_mode="externo", token_externo=tok)
    if any([r1, r2, r3, r4]):
        print("  >> VULNERABLE: el servidor ejecuto comandos sin una sesion autenticada.")
    else:
        print("  >> PROTEGIDO: exige una sesion con token valido en cada comando.")

    print("  -- autorizacion por rol (el invitado solo deberia consultar) --")
    a1 = _escritura(host, puerto, "CMD_ADD como invitado", casa5.CMD_ADD,
                    {CONFIG.F_KEY: "intruso", CONFIG.F_VALUE: "x"})
    a2 = _escritura(host, puerto, "CMD_DEL como invitado", casa5.CMD_DEL,
                    {CONFIG.F_KEY: "mensaje"})
    if a1 or a2:
        print("  >> VULNERABLE: el invitado puede modificar la boveda (sin autorizacion por rol).")
    else:
        print("  >> PROTEGIDO: el invitado solo consulta (ERR_ALLOW al escribir).")


def main():
    if len(sys.argv) < 2:
        print("Uso: python sesion.py <IP> [puerto]")
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Sonda de flujo/token contra {host}:{puerto} (Casa 5) ===")
    correr(host, puerto)


if __name__ == "__main__":
    main()
