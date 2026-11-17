"""Cliente Custodio para conectarse e interactuar por terminal con la Boveda KOOPIS."""

import getpass
import json
import socket
import sys

from red.protocolo import (
    PUERTO_DEFECTO,
    TAMANO_IV,
    TIPO_COMANDO,
    TIPO_ERROR,
    TIPO_HANDSHAKE,
    TIPO_LOGIN,
    TIPO_RESPUESTA,
    ErrorProtocolo,
    empaquetar_cabecera,
    enviar_trama,
    recibir_trama,
)
from red.secuencia import ControlSecuencia
from seguridad.cifrado import cifrar, descifrar, nuevo_iv
from seguridad.handshake import iniciar_handshake, terminar_handshake
from seguridad.integridad import calcular_hmac, verificar_hmac

MAX_INTENTOS_LOGIN = 3
TIMEOUT_CLIENTE_SEG = 20.0


class ClienteCustodio:
    def __init__(self, host="127.0.0.1", puerto=PUERTO_DEFECTO, timeout=TIMEOUT_CLIENTE_SEG):
        self.host = host
        self.puerto = puerto
        self.timeout = timeout
        self.sock = None
        self.secuencia = ControlSecuencia()
        self.k_cif = None
        self.k_int = None

    def conectar(self):
        self.sock = socket.create_connection((self.host, self.puerto), timeout=self.timeout)

    def cerrar(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def hacer_handshake(self):
        secreto_a, payload_hs = iniciar_handshake()
        datos = json.dumps(payload_hs, ensure_ascii=False).encode("utf-8")
        iv_cero = b"\x00" * TAMANO_IV
        seq = self.secuencia.siguiente_envio()
        cabecera = empaquetar_cabecera(len(datos), TIPO_HANDSHAKE, seq, iv_cero)
        firma = calcular_hmac(cabecera, datos, b"")
        enviar_trama(self.sock, TIPO_HANDSHAKE, seq, iv_cero, datos, firma)

        tipo, seq_srv, iv_srv, payload_srv, hmac_srv = recibir_trama(self.sock)
        if not self.secuencia.validar_recepcion(seq_srv):
            raise ErrorProtocolo("Secuencia invalida en handshake")
        if tipo != TIPO_HANDSHAKE or iv_srv != iv_cero:
            raise ErrorProtocolo("Respuesta inesperada durante el handshake")

        cab_srv = empaquetar_cabecera(len(payload_srv), tipo, seq_srv, iv_srv)
        if not verificar_hmac(cab_srv, payload_srv, hmac_srv, b""):
            raise ErrorProtocolo("Firma invalida en handshake")

        claves = terminar_handshake(secreto_a, payload_srv)
        if claves is None:
            raise ErrorProtocolo("El servidor envio parametros DH invalidos")
        self.k_cif, self.k_int = claves

    def _enviar_cifrado(self, tipo, payload_dict):
        if self.k_cif is None or self.k_int is None:
            raise ErrorProtocolo("Handshake no completado")

        datos = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        iv = nuevo_iv()
        payload_cif = cifrar(datos, self.k_cif, iv)
        seq = self.secuencia.siguiente_envio()
        cabecera = empaquetar_cabecera(len(payload_cif), tipo, seq, iv)
        firma = calcular_hmac(cabecera, payload_cif, self.k_int)
        enviar_trama(self.sock, tipo, seq, iv, payload_cif, firma)

    def _recibir_cifrado(self):
        if self.k_cif is None or self.k_int is None:
            raise ErrorProtocolo("Handshake no completado")

        tipo, seq_srv, iv, payload_cif, hmac_rec = recibir_trama(self.sock)
        if not self.secuencia.validar_recepcion(seq_srv):
            raise ErrorProtocolo("Secuencia del servidor fuera de orden")

        cabecera = empaquetar_cabecera(len(payload_cif), tipo, seq_srv, iv)
        if not verificar_hmac(cabecera, payload_cif, hmac_rec, self.k_int):
            raise ErrorProtocolo("Firma HMAC del servidor invalida")

        try:
            texto = descifrar(payload_cif, self.k_cif, iv)
            datos = json.loads(texto.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ErrorProtocolo("Respuesta descifrada mal formada") from exc

        if not isinstance(datos, dict):
            raise ErrorProtocolo("La respuesta del servidor no es un objeto JSON")
        return tipo, datos

    def iniciar_sesion(self, usuario, clave):
        self._enviar_cifrado(TIPO_LOGIN, {"usuario": usuario, "clave": clave})
        return self._recibir_cifrado()

    def enviar_comando(self, payload_dict):
        self._enviar_cifrado(TIPO_COMANDO, payload_dict)
        return self._recibir_cifrado()


def _imprimir_respuesta(tipo, datos):
    if tipo == TIPO_ERROR:
        codigo = datos.get("codigo", "ERROR")
        desc = datos.get("descripcion", "Solicitud rechazada")
        print(f"[Error {codigo}] {desc}")
        return

    mensaje = datos.get("mensaje", "OK")
    print(f"[OK] {mensaje}")
    extra = datos.get("datos")
    if isinstance(extra, dict) and extra:
        for k, v in extra.items():
            print(f"  - {k}: {v}")
    elif isinstance(extra, dict) and "datos" in datos:
        print("  (sin registros)")


def _autenticar_en_terminal(cliente):
    intentos = 0
    while intentos < MAX_INTENTOS_LOGIN:
        usuario = input("Usuario: ").strip()
        if not usuario:
            print("El usuario no puede estar vacio.")
            continue
        clave = getpass.getpass("Clave: ")
        intentos += 1

        tipo, resp = cliente.iniciar_sesion(usuario, clave)
        if tipo == TIPO_RESPUESTA:
            perfil = resp.get("perfil", "desconocido")
            print(f"[OK] Sesion iniciada como '{usuario}' (perfil: {perfil})")
            return perfil

        _imprimir_respuesta(tipo, resp)
        if intentos >= MAX_INTENTOS_LOGIN:
            print("[Custodio] Limite de intentos alcanzado.")
            return None
    return None


def _menu_comandos(cliente, perfil):
    while True:
        print(f"\n--- Menu KOOPIS ({perfil}) ---")
        print("1. consultar")
        print("2. agregar")
        print("3. borrar")
        print("4. cierre_emergencia")
        print("5. salir")

        opcion = input("Opcion: ").strip().lower()

        if opcion in ("5", "salir", "exit", "q"):
            print("[Custodio] Cerrando sesion.")
            return

        if opcion in ("1", "consultar"):
            clave = input("Clave (Enter para consultar todas): ").strip()
            solicitud = {"comando": "consultar", "clave": clave}
        elif opcion in ("2", "agregar"):
            clave = input("Clave: ").strip()
            valor = input("Valor: ")
            solicitud = {"comando": "agregar", "clave": clave, "valor": valor}
        elif opcion in ("3", "borrar"):
            clave = input("Clave a borrar: ").strip()
            solicitud = {"comando": "borrar", "clave": clave}
        elif opcion in ("4", "cierre_emergencia"):
            confirmacion = input("Esto apagara la Boveda y borrara los secretos. Confirmar? (s/N): ").strip().lower()
            if confirmacion not in ("s", "si"):
                print("[Custodio] Operacion cancelada.")
                continue
            solicitud = {"comando": "cierre_emergencia"}
        else:
            print("Opcion no valida.")
            continue

        try:
            tipo, resp = cliente.enviar_comando(solicitud)
        except ValueError as exc:
            print(f"[Custodio] No se pudo enviar la solicitud: {exc}")
            continue

        _imprimir_respuesta(tipo, resp)
        if solicitud["comando"] == "cierre_emergencia" and tipo == TIPO_RESPUESTA:
            print("[Custodio] Boveda cerrada por emergencia.")
            return


def iniciar_cliente(host="127.0.0.1", puerto=PUERTO_DEFECTO):
    cliente = ClienteCustodio(host, puerto)
    try:
        try:
            cliente.conectar()
        except OSError as exc:
            print(f"[Custodio] No se pudo conectar a {host}:{puerto} ({exc})")
            return

        print(f"[Custodio] Conectado a {host}:{puerto}")
        cliente.hacer_handshake()
        print("[Custodio] Handshake completado.")

        perfil = _autenticar_en_terminal(cliente)
        if perfil is None:
            return

        _menu_comandos(cliente, perfil)
    except (ConnectionError, TimeoutError, ErrorProtocolo) as exc:
        print(f"[Custodio] Conexion finalizada: {exc}")
    except (EOFError, KeyboardInterrupt):
        print("\n[Custodio] Saliendo.")
    finally:
        cliente.cerrar()


if __name__ == "__main__":
    destino = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    try:
        puerto_arg = int(sys.argv[2]) if len(sys.argv) > 2 else PUERTO_DEFECTO
    except ValueError:
        print("Uso: python3 -m cliente.custodio [host] [puerto]")
        sys.exit(1)
    iniciar_cliente(destino, puerto_arg)
