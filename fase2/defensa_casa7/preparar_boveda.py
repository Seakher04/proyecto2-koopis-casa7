"""Inicializa o restaura los archivos de datos de la Boveda KOOPIS (Casa 7).

Uso desde la raiz del repositorio:
    python3 -m fase2.defensa_casa7.preparar_boveda
    python3 -m fase2.defensa_casa7.preparar_boveda --forzar
    python3 -m fase2.defensa_casa7.preparar_boveda --restaurar
"""

import argparse
import json
import secrets
import shutil
import sys
from pathlib import Path

from seguridad.login import agregar_usuario

RAIZ_REPO = Path(__file__).resolve().parents[2]
DIR_DATOS_DEFECTO = RAIZ_REPO / "servidor" / "datos"
DIR_RESPALDO_DEFECTO = Path(__file__).resolve().parent / "respaldo_datos"

# Credenciales publicas del asilo documentadas en la Especificacion Publica (pag. 2)
USUARIO_ASILO = "asilo_casa6"
CLAVE_ASILO = "Asilo.Temp.2026#"

SECRETOS_INICIALES = {
    "fragmento_clave_maestra": "K7-9F4A-2026-SIGILO",
    "plano_boveda_norte": "Acceso restringido nivel 3 - Sala de Sellos",
    "clave_rotacion_semanal": "KOOPIS-TURNO-NOVIEMBRE",
}


def _generar_clave() -> str:
    return f"Casa7.{secrets.token_urlsafe(12)}"


def preparar(
    dir_datos: Path = DIR_DATOS_DEFECTO,
    dir_respaldo: Path = DIR_RESPALDO_DEFECTO,
    clave_jefe: str | None = None,
    clave_integrante: str | None = None,
    forzar: bool = False,
) -> dict:
    ruta_usuarios = dir_datos / "usuarios.txt"
    ruta_boveda = dir_datos / "boveda.json"

    if ruta_usuarios.exists() and not forzar:
        raise FileExistsError(
            f"Ya existe {ruta_usuarios}. Usa --forzar para regenerar o --restaurar para recuperar respaldo."
        )

    dir_datos.mkdir(parents=True, exist_ok=True)
    if ruta_usuarios.exists():
        ruta_usuarios.unlink()

    c_jefe = clave_jefe or _generar_clave()
    c_integrante = clave_integrante or _generar_clave()

    agregar_usuario(str(ruta_usuarios), "jefe_casa7", c_jefe, "jefe")
    agregar_usuario(str(ruta_usuarios), "custodio_casa7", c_integrante, "integrante")
    agregar_usuario(str(ruta_usuarios), USUARIO_ASILO, CLAVE_ASILO, "hacinado")

    ruta_boveda.write_text(
        json.dumps(SECRETOS_INICIALES, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    dir_respaldo.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ruta_usuarios, dir_respaldo / "usuarios.txt")
    shutil.copy2(ruta_boveda, dir_respaldo / "boveda.json")

    return {
        "usuarios": {
            "jefe_casa7": ("jefe", c_jefe),
            "custodio_casa7": ("integrante", c_integrante),
            USUARIO_ASILO: ("hacinado", CLAVE_ASILO),
        },
        "ruta_usuarios": str(ruta_usuarios),
        "ruta_boveda": str(ruta_boveda),
        "ruta_respaldo": str(dir_respaldo),
        "cantidad_secretos": len(SECRETOS_INICIALES),
    }


def restaurar(
    dir_datos: Path = DIR_DATOS_DEFECTO,
    dir_respaldo: Path = DIR_RESPALDO_DEFECTO,
) -> None:
    resp_usuarios = dir_respaldo / "usuarios.txt"
    resp_boveda = dir_respaldo / "boveda.json"
    if not resp_usuarios.exists() or not resp_boveda.exists():
        raise FileNotFoundError(
            f"No existe un respaldo completo en {dir_respaldo}. Ejecuta primero preparar_boveda.py."
        )
    dir_datos.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resp_usuarios, dir_datos / "usuarios.txt")
    shutil.copy2(resp_boveda, dir_datos / "boveda.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepara o restaura usuarios.txt y boveda.json para la Boveda KOOPIS."
    )
    parser.add_argument("--dir-datos", type=Path, default=DIR_DATOS_DEFECTO)
    parser.add_argument("--dir-respaldo", type=Path, default=DIR_RESPALDO_DEFECTO)
    parser.add_argument("--clave-jefe", default=None, help="Clave para jefe_casa7 (12-128 chars).")
    parser.add_argument("--clave-integrante", default=None, help="Clave para custodio_casa7 (12-128 chars).")
    parser.add_argument("--forzar", action="store_true", help="Sobrescribe usuarios.txt y boveda.json.")
    parser.add_argument("--restaurar", action="store_true", help="Restaura desde el respaldo guardado.")
    args = parser.parse_args()

    try:
        if args.restaurar:
            restaurar(args.dir_datos, args.dir_respaldo)
            print(f"[OK] Datos restaurados en {args.dir_datos} desde {args.dir_respaldo}")
            return

        res = preparar(
            dir_datos=args.dir_datos,
            dir_respaldo=args.dir_respaldo,
            clave_jefe=args.clave_jefe,
            clave_integrante=args.clave_integrante,
            forzar=args.forzar,
        )
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"[Error] {exc}", file=sys.stderr)
        sys.exit(1)

    print("[OK] Boveda KOOPIS preparada correctamente:")
    print(f"  - Usuarios : {res['ruta_usuarios']}")
    print(f"  - Boveda   : {res['ruta_boveda']} ({res['cantidad_secretos']} secretos iniciales)")
    print(f"  - Respaldo : {res['ruta_respaldo']}")
    print("\nCredenciales creadas (anota las generadas, no se guardan en claro):")
    for usuario, (perfil, clave) in res["usuarios"].items():
        print(f"  - {usuario:<16} ({perfil:<10}) | clave: {clave}")


if __name__ == "__main__":
    main()
