import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from red.defensa import RegistroDefensivo
from red.protocolo import (
    HOST_DEFECTO,
    PUERTO_DEFECTO,
    ErrorProtocolo,
    empaquetar_cabecera,
    enviar_trama,
    recibir_trama,
)
from red.secuencia import ControlSecuencia
from seguridad.cifrado import cifrar, descifrar, nuevo_iv
from seguridad.handshake import procesar_handshake
from seguridad.integridad import calcular_hmac, verificar_hmac
from seguridad.login import cargar_usuarios, verificar_credenciales
from servidor.comandos import procesar_comando

TIPO_HANDSHAKE = 0x01
TIPO_LOGIN = 0x02
TIPO_COMANDO = 0x03
TIPO_RESPUESTA_OK = 0x04
TIPO_ERROR = 0x05

RUTA_USUARIOS = Path(__file__).resolve().parent / "datos" / "usuarios.txt"

# Segundos sin recibir nada antes de cerrar: menos antes del login, más con sesión iniciada
TIEMPO_SIN_SESION = 60
TIEMPO_CON_SESION = 300

# Los comandos leen y escriben boveda.json: uno a la vez entre todos los hilos
_candado_boveda = threading.Lock()
_cierre_en_curso = False


# =====================================================================
# Paquetes sobre la capa de red (red/protocolo.py)
# =====================================================================


def _construir_cabecera(longitud: int, tipo: int, nonce: int, iv: bytes) -> bytes:
    return empaquetar_cabecera(longitud, tipo, nonce, iv)


def _leer_paquete(
    sock: socket.socket,
) -> tuple[bytes, int, int, bytes, bytes, bytes] | None:
    """Lee una trama completa (lo usan las pruebas). None si se cerró o la trama no sirve."""
    try:
        tipo, nonce, iv, payload_cifrado, hmac_recibido = recibir_trama(sock)
    except (OSError, ErrorProtocolo):
        return None
    cabecera = _construir_cabecera(len(payload_cifrado), tipo, nonce, iv)
    return cabecera, tipo, nonce, iv, payload_cifrado, hmac_recibido


def _enviar_paquete(
    sock: socket.socket,
    tipo: int,
    nonce: int,
    payload_dict: dict,
    k_cif: bytes | None,
    k_int: bytes | None,
) -> None:
    payload_bytes = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    if tipo == TIPO_HANDSHAKE:
        iv = b"\x00" * 16
        payload_final = payload_bytes
        clave_hmac = b""
    else:
        if k_cif is None or k_int is None:
            raise ValueError("Se requieren claves de sesión para enviar paquetes cifrados")
        iv = nuevo_iv()
        payload_final = cifrar(payload_bytes, k_cif, iv)
        clave_hmac = k_int

    cabecera = _construir_cabecera(len(payload_final), tipo, nonce, iv)
    firma = calcular_hmac(cabecera, payload_final, clave_hmac)
    enviar_trama(sock, tipo, nonce, iv, payload_final, firma)


def _cargar_usuarios_o_salir() -> dict:
    """Lee servidor/datos/usuarios.txt. Sin usuarios la Bóveda no arranca."""
    usuarios = cargar_usuarios(RUTA_USUARIOS) if RUTA_USUARIOS.exists() else {}
    if not usuarios:
        print(f"[Boveda] No hay usuarios en {RUTA_USUARIOS}")
        print("Crearlos con: python3 -m seguridad.login servidor/datos/usuarios.txt <usuario> <perfil>")
        sys.exit(1)
    return usuarios


# =====================================================================
# Flujo principal del servidor de bóveda
# =====================================================================


def manejar_cliente(
    conn: socket.socket,
    servidor_sock: socket.socket | None = None,
    usuarios: dict | None = None,
    ip: str | None = None,
    defensa: RegistroDefensivo | None = None,
) -> None:
    usuarios = usuarios or {}
    handshake_completado = False
    k_cif: bytes | None = None
    k_int: bytes | None = None
    secuencia = ControlSecuencia()

    sesion = {
        "autenticado": False,
        "perfil": None,
        "intentos_fallidos": 0,
        "cerrar_servidor": False,
    }

    def enviar_respuesta(tipo: int, payload: dict) -> None:
        _enviar_paquete(conn, tipo, secuencia.siguiente_envio(), payload, k_cif, k_int)

    def anotar_falta(motivo: str) -> None:
        """Deja el intento inválido en la bitácora de red/defensa.py y frena un poco al cliente."""
        if defensa is not None and ip is not None:
            time.sleep(defensa.registrar_anomalia(ip, motivo))

    conn.settimeout(TIEMPO_SIN_SESION)
    try:
        while True:
            try:
                tipo, nonce, iv, payload_cifrado, hmac_recibido = recibir_trama(conn)
            except ErrorProtocolo:
                anotar_falta("trama_invalida")
                break
            except OSError:
                # Conexión cerrada, cortada de golpe o sin actividad
                break
            cabecera = _construir_cabecera(len(payload_cifrado), tipo, nonce, iv)

            # 1. Antes del Handshake
            if not handshake_completado:
                if (
                    tipo != TIPO_HANDSHAKE
                    or iv != b"\x00" * 16
                    or not secuencia.validar_recepcion(nonce)
                    or not verificar_hmac(cabecera, payload_cifrado, hmac_recibido, b"")
                ):
                    anotar_falta("handshake_invalido")
                    break
                resultado_hs = procesar_handshake(payload_cifrado)
                if resultado_hs is None:
                    anotar_falta("handshake_invalido")
                    break

                pub_b_hex, k_cif, k_int = resultado_hs
                handshake_completado = True
                enviar_respuesta(TIPO_HANDSHAKE, {"grupo": 14, "B": pub_b_hex})
                continue

            # 2. Después del Handshake
            if tipo == TIPO_HANDSHAKE:
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "HANDSHAKE_DUPLICADO",
                        "descripcion": "El handshake ya fue completado",
                    },
                )
                anotar_falta("handshake_duplicado")
                break

            if not secuencia.validar_recepcion(nonce):
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "NONCE_INVALIDO",
                        "descripcion": "Número de secuencia fuera de orden",
                    },
                )
                anotar_falta("nonce_invalido")
                break

            if k_int is None or not verificar_hmac(
                cabecera, payload_cifrado, hmac_recibido, k_int
            ):
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "INTEGRIDAD",
                        "descripcion": "Firma HMAC inválida",
                    },
                )
                anotar_falta("hmac_invalido")
                break

            try:
                if k_cif is None:
                    raise ValueError("Falta la clave de cifrado")
                texto_plano = descifrar(payload_cifrado, k_cif, iv)
                payload_dict = json.loads(texto_plano.decode("utf-8"))
                if not isinstance(payload_dict, dict):
                    raise TypeError("El JSON descifrado no es un objeto")
            except (UnicodeDecodeError, TypeError, ValueError, RecursionError):
                enviar_respuesta(
                    TIPO_ERROR,
                    {
                        "codigo": "FORMATO_INVALIDO",
                        "descripcion": "El payload descifrado no es JSON válido",
                    },
                )
                anotar_falta("formato_invalido")
                break

            # 3. Flujo de Login (0x02)
            if tipo == TIPO_LOGIN:
                if sesion["autenticado"]:
                    enviar_respuesta(
                        TIPO_ERROR,
                        {
                            "codigo": "SESION",
                            "descripcion": "Sesión ya iniciada",
                        },
                    )
                    continue

                usuario = payload_dict.get("usuario")
                password = payload_dict.get("clave", payload_dict.get("password"))
                perfil = verificar_credenciales(usuarios, usuario, password)

                if perfil is None:
                    sesion["intentos_fallidos"] += 1
                    enviar_respuesta(
                        TIPO_ERROR,
                        {
                            "codigo": "CREDENCIALES",
                            "descripcion": "Credenciales inválidas",
                        },
                    )
                    anotar_falta("credenciales")
                    if sesion["intentos_fallidos"] >= 3:
                        break
                    continue

                sesion["autenticado"] = True
                sesion["perfil"] = perfil
                conn.settimeout(TIEMPO_CON_SESION)
                enviar_respuesta(
                    TIPO_RESPUESTA_OK,
                    {
                        "estado": "OK",
                        "mensaje": "Sesión iniciada",
                        "perfil": perfil,
                    },
                )
                continue

            # 4. Flujo de Comandos (0x03)
            if tipo == TIPO_COMANDO:
                global _cierre_en_curso
                with _candado_boveda:
                    if _cierre_en_curso:
                        break
                    tipo_resp, dict_resp = procesar_comando(payload_dict, sesion)
                    if sesion.get("cerrar_servidor"):
                        _cierre_en_curso = True
                        try:
                            enviar_respuesta(tipo_resp, dict_resp)
                        except OSError:
                            pass
                        conn.close()
                        if servidor_sock is not None:
                            servidor_sock.close()
                        sys.exit(0)
                enviar_respuesta(tipo_resp, dict_resp)
                continue

            # Cualquier otro tipo no esperado tras el handshake
            enviar_respuesta(
                TIPO_ERROR,
                {
                    "codigo": "SOLICITUD_INVALIDA",
                    "descripcion": "Tipo de mensaje no soportado",
                },
            )
            anotar_falta("tipo_no_soportado")
            break
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _atender(
    conn: socket.socket,
    ip: str,
    servidor_sock: socket.socket,
    usuarios: dict,
    defensa: RegistroDefensivo,
) -> None:
    """Hilo de un custodio. Un error de un cliente cierra solo su conexión, nunca la Bóveda."""
    try:
        manejar_cliente(conn, servidor_sock, usuarios, ip, defensa)
    except SystemExit:
        # Cierre de emergencia: se termina el proceso entero, con todas las conexiones adentro
        print("[Boveda] Cierre de emergencia ejecutado", flush=True)
        os._exit(0)
    except Exception as error:
        defensa.registrar_anomalia(ip, "excepcion", type(error).__name__)
    finally:
        defensa.liberar_conexion(ip)


def iniciar_servidor(host: str = HOST_DEFECTO, puerto: int = PUERTO_DEFECTO) -> None:
    global _cierre_en_curso
    _cierre_en_curso = False
    usuarios = _cargar_usuarios_o_salir()
    defensa = RegistroDefensivo()
    servidor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor_sock.bind((host, puerto))
    servidor_sock.listen(defensa.max_conexiones)
    print(f"[Boveda] Escuchando en {host}:{puerto} ({len(usuarios)} usuarios)", flush=True)

    try:
        while True:
            try:
                conn, (ip, _puerto) = servidor_sock.accept()
            except OSError:
                if servidor_sock.fileno() == -1:
                    break
                continue
            # red/defensa.py decide si la IP está bloqueada o ya tiene demasiadas conexiones
            if not defensa.adquirir_conexion(ip):
                conn.close()
                continue
            threading.Thread(
                target=_atender,
                args=(conn, ip, servidor_sock, usuarios, defensa),
                daemon=True,
            ).start()
    finally:
        try:
            servidor_sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    iniciar_servidor()
