"""Genera trafico legitimo de Custodio contra la Boveda KOOPIS (Casa 7).

Util para:
- Ensayar localmente en 127.0.0.1 el flujo completo + logs + Wireshark.
- Generar actividad legitima de fondo en el laboratorio si se requiere.

Uso desde la raiz del repositorio:
    python3 -m fase2.defensa_casa7.trafico_legitimo --usuario jefe_casa7 --clave <CLAVE>
    python3 -m fase2.defensa_casa7.trafico_legitimo --host 10.1.138.56 --usuario custodio_casa7 --clave <CLAVE> --rondas 3 --pausa 2
"""

import argparse
import sys
import time

from cliente.custodio import ClienteCustodio
from red.protocolo import PUERTO_DEFECTO, TIPO_RESPUESTA, ErrorProtocolo


def ejecutar_ronda(
    host: str,
    puerto: int,
    usuario: str,
    clave: str,
    ronda: int,
    limpiar: bool = False,
) -> bool:
    cliente = ClienteCustodio(host=host, puerto=puerto)
    clave_tmp = f"registro_ronda_{ronda}"
    try:
        cliente.conectar()
        cliente.hacer_handshake()
        tipo_login, resp_login = cliente.iniciar_sesion(usuario, clave)
        if tipo_login != TIPO_RESPUESTA:
            print(f"[Ronda {ronda}] Login rechazado: {resp_login}")
            return False

        perfil = resp_login.get("perfil", "desconocido")
        print(f"[Ronda {ronda}] Login OK como '{usuario}' (perfil: {perfil})")

        # 1. Consultar toda la boveda
        tipo_c, resp_c = cliente.enviar_comando({"comando": "consultar", "clave": ""})
        estado_c = "OK" if tipo_c == TIPO_RESPUESTA else f"ERROR:{resp_c.get('codigo')}"
        n_claves = len(resp_c.get("datos", {})) if tipo_c == TIPO_RESPUESTA else 0
        print(f"[Ronda {ronda}] consultar('') -> {estado_c} ({n_claves} claves)")

        # 2. Agregar registro operativo
        tipo_a, resp_a = cliente.enviar_comando(
            {
                "comando": "agregar",
                "clave": clave_tmp,
                "valor": f"verificacion_operativa_{ronda}",
            }
        )
        estado_a = "OK" if tipo_a == TIPO_RESPUESTA else f"ERROR:{resp_a.get('codigo')}"
        print(f"[Ronda {ronda}] agregar('{clave_tmp}') -> {estado_a}")

        # 3. Consultar clave recien agregada
        tipo_g, resp_g = cliente.enviar_comando({"comando": "consultar", "clave": clave_tmp})
        estado_g = "OK" if tipo_g == TIPO_RESPUESTA else f"ERROR:{resp_g.get('codigo')}"
        print(f"[Ronda {ronda}] consultar('{clave_tmp}') -> {estado_g}")

        # 4. Opcional: borrar registro temporal (solo tiene permiso 'jefe')
        if limpiar and perfil == "jefe":
            tipo_b, resp_b = cliente.enviar_comando({"comando": "borrar", "clave": clave_tmp})
            estado_b = "OK" if tipo_b == TIPO_RESPUESTA else f"ERROR:{resp_b.get('codigo')}"
            print(f"[Ronda {ronda}] borrar('{clave_tmp}') -> {estado_b}")

        return True
    except (OSError, ErrorProtocolo) as exc:
        print(f"[Ronda {ronda}] Error de red/protocolo: {exc}", file=sys.stderr)
        return False
    finally:
        cliente.cerrar()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simula sesiones legitimas de Custodio contra la Boveda KOOPIS."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=PUERTO_DEFECTO)
    parser.add_argument("--usuario", required=True)
    parser.add_argument("--clave", required=True)
    parser.add_argument("--rondas", type=int, default=1, help="Cantidad de sesiones a ejecutar.")
    parser.add_argument("--pausa", type=float, default=1.0, help="Segundos entre rondas.")
    parser.add_argument(
        "--limpiar",
        action="store_true",
        help="Si el usuario es jefe, borra la clave temporal agregada al final de cada ronda.",
    )
    args = parser.parse_args()

    exitosas = 0
    for i in range(1, args.rondas + 1):
        if ejecutar_ronda(args.host, args.puerto, args.usuario, args.clave, i, args.limpiar):
            exitosas += 1
        if i < args.rondas and args.pausa > 0:
            time.sleep(args.pausa)

    print(f"\n[Resumen] Rondas exitosas: {exitosas}/{args.rondas}")
    if exitosas == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
