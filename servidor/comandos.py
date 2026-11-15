import json
from pathlib import Path

TIPO_RESPUESTA_OK = 0x04
TIPO_ERROR = 0x05

RUTA_BOVEDA = Path(__file__).resolve().parent / "datos" / "boveda.json"

PERMISOS_COMANDOS = {
    "consultar": {"integrante", "jefe"},
    "agregar": {"integrante", "jefe"},
    "borrar": {"jefe"},
    "cierre_emergencia": {"jefe"},
}


def _asegurar_archivo_boveda(ruta: Path | None = None) -> Path:
    destino = Path(ruta) if ruta is not None else RUTA_BOVEDA
    destino.parent.mkdir(parents=True, exist_ok=True)
    if not destino.exists():
        destino.write_text("{}", encoding="utf-8")
    return destino


def _cargar_boveda(ruta: Path | None = None) -> dict:
    destino = _asegurar_archivo_boveda(ruta)
    contenido = destino.read_text(encoding="utf-8").strip()
    if not contenido:
        destino.write_text("{}", encoding="utf-8")
        return {}
    datos = json.loads(contenido)
    if not isinstance(datos, dict):
        return {}
    return datos


def _guardar_boveda(datos: dict, ruta: Path | None = None) -> None:
    destino = _asegurar_archivo_boveda(ruta)
    destino.write_text(
        json.dumps(datos, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _error(codigo: str, descripcion: str) -> tuple[int, dict]:
    return TIPO_ERROR, {"codigo": codigo, "descripcion": descripcion}


def _respuesta_ok(mensaje: str, datos: dict) -> tuple[int, dict]:
    return TIPO_RESPUESTA_OK, {"estado": "OK", "mensaje": mensaje, "datos": datos}


def procesar_comando(payload_dict: dict, sesion: dict) -> tuple[int, dict]:
    """Procesa un comando de la bóveda validando sesión, permisos y estructura."""
    _asegurar_archivo_boveda()

    if not isinstance(sesion, dict) or not sesion.get("autenticado", False):
        return _error("NO_AUTENTICADO", "Sesión no autenticada")

    if not isinstance(payload_dict, dict):
        return _error("SOLICITUD_INVALIDA", "El formato de la solicitud es inválido")

    comando = payload_dict.get("comando")
    if not isinstance(comando, str) or comando not in PERMISOS_COMANDOS:
        return _error("SOLICITUD_INVALIDA", "Comando desconocido o ausente")

    perfil = sesion.get("perfil")
    if perfil not in PERMISOS_COMANDOS[comando]:
        return _error("NO_AUTORIZADO", "El perfil actual no tiene permisos para este comando")

    if comando == "consultar":
        if "clave" not in payload_dict or not isinstance(payload_dict["clave"], str):
            return _error("SOLICITUD_INVALIDA", "Falta la llave obligatoria 'clave'")
        clave = payload_dict["clave"]
        boveda = _cargar_boveda()
        if clave == "":
            return _respuesta_ok("Consulta general realizada", boveda)
        if clave not in boveda:
            return _error("NO_ENCONTRADO", f"La clave '{clave}' no existe")
        return _respuesta_ok("Consulta realizada", {clave: boveda[clave]})

    if comando == "agregar":
        if (
            "clave" not in payload_dict
            or "valor" not in payload_dict
            or not isinstance(payload_dict["clave"], str)
            or not isinstance(payload_dict["valor"], str)
            or payload_dict["clave"] == ""
        ):
            return _error(
                "SOLICITUD_INVALIDA",
                "Faltan llaves obligatorias 'clave' o 'valor'",
            )
        clave = payload_dict["clave"]
        valor = payload_dict["valor"]
        boveda = _cargar_boveda()
        boveda[clave] = valor
        _guardar_boveda(boveda)
        return _respuesta_ok("Elemento guardado correctamente", {})

    if comando == "borrar":
        if (
            "clave" not in payload_dict
            or not isinstance(payload_dict["clave"], str)
            or payload_dict["clave"] == ""
        ):
            return _error("SOLICITUD_INVALIDA", "Falta la llave obligatoria 'clave'")
        clave = payload_dict["clave"]
        boveda = _cargar_boveda()
        if clave not in boveda:
            return _error("NO_ENCONTRADO", f"La clave '{clave}' no existe")
        del boveda[clave]
        _guardar_boveda(boveda)
        return _respuesta_ok("Elemento eliminado correctamente", {})

    if comando == "cierre_emergencia":
        _guardar_boveda({})
        sesion["cerrar_servidor"] = True
        return _respuesta_ok("Cierre de emergencia ejecutado", {})
    
    return _error("SOLICITUD_INVALIDA", "Comando no reconocido")
