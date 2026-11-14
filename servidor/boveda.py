"""Servidor TCP de la Boveda"""

import socket
import threading

from red.defensa import RegistroDefensivo
from red.protocolo import (
    HOST_DEFECTO,
    PUERTO_DEFECTO,
    ErrorProtocolo,
    construir_error_generico,
    recibir_trama,
)
from red.secuencia import ControlSecuencia

TIMEOUT_INACTIVO_SEG = 60.0
TIMEOUT_TRAMA_SEG = 10.0


def atender_cliente(conn, addr, defensa):
    ip = addr[0]
    secuencia = ControlSecuencia()

    try:
        conn.settimeout(TIMEOUT_INACTIVO_SEG)
        while True:
            try:
                tipo, seq_recibido, iv, payload, hmac_tag = recibir_trama(
                    conn, timeout_trama=TIMEOUT_TRAMA_SEG
                )
            except TimeoutError:
                # Cliente inactivo sin iniciar trama: cerrar sin penalizar IP
                break
            except (ConnectionError, OSError):
                break
            except ErrorProtocolo as exc:
                # Si la trama viene mal formada el flujo TCP queda desincronizado: cerra
                defensa.registrar_anomalia(ip, "trama_invalida", str(exc))
                try:
                    conn.sendall(construir_error_generico(secuencia.siguiente_envio()))
                except OSError:
                    pass
                break

            if not secuencia.validar_recepcion(seq_recibido):
                esperado = secuencia.seq_esperado
                defensa.registrar_anomalia(
                    ip,
                    "secuencia_invalida",
                    f"esperado={esperado} recibido={seq_recibido}",
                )
                try:
                    conn.sendall(construir_error_generico(secuencia.siguiente_envio()))
                except OSError:
                    pass
                break

            # TODO: conectar handshake (0x01), login (0x02), HMAC, cifrado y comandos (0x03)
            # TODO: manejar cierre_emergencia (apagar servidor y rechazar conexiones nuevas)
            print(f"[Boveda] Trama recibida desde {ip}: tipo={tipo:#x} seq={seq_recibido} len={len(payload)}")
            break
    finally:
        try:
            conn.close()
        except OSError:
            pass
        defensa.liberar_conexion(ip)


def iniciar_servidor(host=HOST_DEFECTO, puerto=PUERTO_DEFECTO):
    defensa = RegistroDefensivo()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, puerto))
        srv.listen(32)
        print(f"[Boveda KOOPIS] Escuchando en {host}:{puerto}")
        try:
            while True:
                conn, addr = srv.accept()
                ip = addr[0]
                if not defensa.adquirir_conexion(ip):
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue

                try:
                    hilo = threading.Thread(
                        target=atender_cliente,
                        args=(conn, addr, defensa),
                        daemon=True,
                    )
                    hilo.start()
                except Exception:
                    defensa.liberar_conexion(ip)
                    conn.close()
        except KeyboardInterrupt:
            print("\n[Boveda KOOPIS] Servidor detenido")


if __name__ == "__main__":
    iniciar_servidor()
