"""Analizador de servidor/datos/alertas_red.log para el Post-mortem (Casa 7).

Uso desde la raiz del repositorio:
    python3 -m fase2.defensa_casa7.analizar_log
    python3 -m fase2.defensa_casa7.analizar_log --ip 10.1.138.42
    python3 -m fase2.defensa_casa7.analizar_log --solo-alertas
    python3 -m fase2.defensa_casa7.analizar_log --log fase2/defensa_casa7/evidencia/alertas_red_casa7.log
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from red.defensa import RUTA_LOG_DEFECTO

PATRON_LINEA = re.compile(
    r"^\[(?P<hora>[^\]]+)\]\s+"
    r"nivel=(?P<nivel>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"evento=(?P<evento>\S+)"
    r"(?:\s+conteo=(?P<conteo>\d+))?"
    r"(?:\s+detalle=(?P<detalle>.*))?$"
)


def parsear_log(ruta: Path) -> list[dict]:
    if not ruta.exists():
        raise FileNotFoundError(f"No se encontro el archivo de log: {ruta}")

    registros = []
    for num, linea in enumerate(ruta.read_text(encoding="utf-8").splitlines(), 1):
        linea = linea.strip()
        if not linea:
            continue
        m = PATRON_LINEA.match(linea)
        if not m:
            registros.append(
                {
                    "linea": num,
                    "hora": "-",
                    "nivel": "RAW",
                    "ip": "-",
                    "evento": "linea_no_reconocida",
                    "conteo": None,
                    "detalle": linea,
                }
            )
            continue
        registros.append(
            {
                "linea": num,
                "hora": m.group("hora"),
                "nivel": m.group("nivel"),
                "ip": m.group("ip"),
                "evento": m.group("evento"),
                "conteo": int(m.group("conteo")) if m.group("conteo") else None,
                "detalle": (m.group("detalle") or "").strip(),
            }
        )
    return registros


def _extraer_kv(detalle: str) -> dict[str, str]:
    pares = {}
    for token in detalle.split():
        if "=" in token:
            k, v = token.split("=", 1)
            pares[k] = v
    return pares


def imprimir_reporte(
    registros: list[dict],
    filtro_ip: str | None = None,
    solo_alertas: bool = False,
    max_timeline: int = 30,
) -> None:
    filtrados = [
        r
        for r in registros
        if (filtro_ip is None or r["ip"] == filtro_ip)
        and (not solo_alertas or r["nivel"] == "ALERTA")
    ]

    if not filtrados:
        print("No hay eventos que coincidan con el filtro indicado.")
        return

    niveles = Counter(r["nivel"] for r in filtrados)
    eventos = Counter(r["evento"] for r in filtrados)
    por_ip = defaultdict(lambda: Counter())
    logins_ok = []
    credenciales_fallidas = Counter()
    comandos = []

    for r in filtrados:
        por_ip[r["ip"]][r["nivel"]] += 1
        por_ip[r["ip"]]["TOTAL"] += 1
        kv = _extraer_kv(r["detalle"])

        if r["evento"] == "login_ok":
            logins_ok.append((r["hora"], r["ip"], kv.get("usuario", "-"), kv.get("perfil", "-")))
        elif r["evento"] == "credenciales":
            credenciales_fallidas[(r["ip"], kv.get("usuario", "-"))] += 1
        elif r["evento"] in ("comando_ok", "comando_error", "cierre_emergencia"):
            comandos.append(r)

    print("=" * 72)
    print("RESUMEN DE BITACORA - BOVEDA KOOPIS (CASA 7)")
    print("=" * 72)
    print(f"Rango temporal : {filtrados[0]['hora']}  -->  {filtrados[-1]['hora']}")
    print(f"Total eventos  : {len(filtrados)} (INFO={niveles['INFO']}, ALERTA={niveles['ALERTA']})")
    if filtro_ip:
        print(f"Filtro IP      : {filtro_ip}")

    print("\n--- Actividad por IP ---")
    for ip, conteos in sorted(por_ip.items(), key=lambda x: x[1]["TOTAL"], reverse=True):
        print(f"  {ip:<18} total={conteos['TOTAL']:<4} INFO={conteos['INFO']:<4} ALERTA={conteos['ALERTA']}")

    print("\n--- Conteo por tipo de evento ---")
    for evento, cant in eventos.most_common():
        print(f"  {evento:<24} {cant}")

    print("\n--- Autenticacion ---")
    if logins_ok:
        print("  Logins exitosos:")
        for hora, ip, usr, perf in logins_ok:
            print(f"    [{hora}] ip={ip} usuario={usr} perfil={perf}")
    else:
        print("  Logins exitosos: ninguno")

    if credenciales_fallidas:
        print("  Intentos fallidos (ip, usuario):")
        for (ip, usr), cant in credenciales_fallidas.most_common():
            print(f"    ip={ip} usuario={usr} intentos={cant}")
    else:
        print("  Intentos fallidos: ninguno")

    print("\n--- Comandos (ok / error / cierre_emergencia) ---")
    if comandos:
        for r in comandos:
            print(f"  [{r['hora']}] ip={r['ip']} {r['evento']} | {r['detalle']}")
    else:
        print("  Sin comandos registrados")

    alertas = [r for r in filtrados if r["nivel"] == "ALERTA"]
    print(f"\n--- Alertas de seguridad ({len(alertas)}) ---")
    if alertas:
        for r in alertas[:max_timeline]:
            extra = f" | {r['detalle']}" if r["detalle"] else ""
            cnt = f" (conteo={r['conteo']})" if r["conteo"] is not None else ""
            print(f"  [{r['hora']}] ip={r['ip']} {r['evento']}{cnt}{extra}")
        if len(alertas) > max_timeline:
            print(f"  ... ({len(alertas) - max_timeline} alertas adicionales omitidas; usa --max-timeline)")
    else:
        print("  Sin alertas registradas")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Genera un resumen de alertas_red.log para el Post-mortem."
    )
    parser.add_argument("--log", type=Path, default=RUTA_LOG_DEFECTO)
    parser.add_argument("--ip", default=None, help="Filtrar por una IP especifica.")
    parser.add_argument("--solo-alertas", action="store_true", help="Mostrar unicamente nivel=ALERTA.")
    parser.add_argument("--max-timeline", type=int, default=30, help="Maximo de alertas a imprimir.")
    args = parser.parse_args()

    try:
        registros = parsear_log(args.log)
    except FileNotFoundError as exc:
        print(f"[Error] {exc}", file=sys.stderr)
        sys.exit(1)

    imprimir_reporte(
        registros,
        filtro_ip=args.ip,
        solo_alertas=args.solo_alertas,
        max_timeline=args.max_timeline,
    )


if __name__ == "__main__":
    main()
