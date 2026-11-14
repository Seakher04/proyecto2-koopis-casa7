"""Framing TCP y formato binario de mensajes para el protocolo KOOPIS."""

import json
import socket
import struct
import time

HOST_DEFECTO = "0.0.0.0"  # Escucha en todas las interfaces (local y red del lab)
PUERTO_DEFECTO = 7777

# Cabecera fija de 29 bytes en big-endian: L (4B), tipo (1B), secuencia (8B), iv (16B)
FORMATO_CABECERA = "!IBQ16s"
TAMANO_CABECERA = struct.calcsize(FORMATO_CABECERA)
TAMANO_IV = 16
TAMANO_HMAC = 32
TAMANO_MAX_PAYLOAD = 16384
MAX_SECUENCIA = (1 << 64) - 1

TIPO_HANDSHAKE = 0x01
TIPO_LOGIN = 0x02
TIPO_COMANDO = 0x03
TIPO_RESPUESTA = 0x04
TIPO_ERROR = 0x05

TIPOS_VALIDOS = {
    TIPO_HANDSHAKE,
    TIPO_LOGIN,
    TIPO_COMANDO,
    TIPO_RESPUESTA,
    TIPO_ERROR,
}


class ErrorProtocolo(Exception):
    pass


def empaquetar_cabecera(longitud, tipo, secuencia, iv):
    if longitud < 0 or longitud > TAMANO_MAX_PAYLOAD:
        raise ValueError(f"Longitud fuera de rango: {longitud}")
    if tipo not in TIPOS_VALIDOS:
        raise ValueError(f"Tipo de mensaje no valido: {tipo}")
    if secuencia < 0 or secuencia > MAX_SECUENCIA:
        raise ValueError(f"Secuencia fuera de rango: {secuencia}")
    if len(iv) != TAMANO_IV:
        raise ValueError(f"El IV debe medir {TAMANO_IV} bytes")
    return struct.pack(FORMATO_CABECERA, longitud, tipo, secuencia, iv)


def desempaquetar_cabecera(cabecera):
    if len(cabecera) != TAMANO_CABECERA:
        raise ErrorProtocolo("Cabecera incompleta")
    longitud, tipo, secuencia, iv = struct.unpack(FORMATO_CABECERA, cabecera)
    if longitud > TAMANO_MAX_PAYLOAD:
        raise ErrorProtocolo(f"Payload excede limite ({longitud} bytes)")
    if tipo not in TIPOS_VALIDOS:
        raise ErrorProtocolo(f"Tipo desconocido ({tipo:#x})")
    return longitud, tipo, secuencia, iv


def _leer_con_limite(sock, cantidad, deadline):
    """Lee `cantidad` bytes sin exceder `deadline` (si no es None)."""
    if cantidad == 0:
        return b""

    partes = []
    recibidos = 0
    while recibidos < cantidad:
        if deadline is not None:
            restante = deadline - time.monotonic()
            if restante <= 0:
                raise ErrorProtocolo("Tiempo agotado completando trama")
            sock.settimeout(restante)

        try:
            bloque = sock.recv(cantidad - recibidos)
        except TimeoutError as exc:
            if deadline is not None:
                raise ErrorProtocolo("Tiempo agotado completando trama") from exc
            raise

        if not bloque:
            raise ConnectionError("Conexion cerrada antes de completar la trama")
        partes.append(bloque)
        recibidos += len(bloque)

    return b"".join(partes)


def recibir_exacto(sock, cantidad):
    """Lee del socket en ciclo hasta completar exactamente `cantidad` bytes."""
    return _leer_con_limite(sock, cantidad, None)


def construir_trama(tipo, secuencia, iv, payload, hmac_tag):
    if len(hmac_tag) != TAMANO_HMAC:
        raise ValueError(f"El HMAC debe medir {TAMANO_HMAC} bytes")
    cabecera = empaquetar_cabecera(len(payload), tipo, secuencia, iv)
    return cabecera + payload + hmac_tag


def enviar_trama(sock, tipo, secuencia, iv, payload, hmac_tag):
    trama = construir_trama(tipo, secuencia, iv, payload, hmac_tag)
    sock.sendall(trama)


def recibir_trama(sock, timeout_trama=10.0):
    """Lee una trama completa y protege contra envios lentos a medias."""
    timeout_original = sock.gettimeout()
    try:
        # El primer byte usa el timeout de sesion; si no llega nada, es un timeout inactivo normal
        primer_bloque = sock.recv(TAMANO_CABECERA)
        if not primer_bloque:
            raise ConnectionError("Conexion cerrada por el extremo remoto")

        deadline = time.monotonic() + timeout_trama if timeout_trama else None

        faltante_cab = TAMANO_CABECERA - len(primer_bloque)
        cabecera = primer_bloque + _leer_con_limite(sock, faltante_cab, deadline)

        longitud, tipo, secuencia, iv = desempaquetar_cabecera(cabecera)
        resto = _leer_con_limite(sock, longitud + TAMANO_HMAC, deadline)
        return tipo, secuencia, iv, resto[:longitud], resto[longitud:]
    finally:
        try:
            sock.settimeout(timeout_original)
        except OSError:
            pass


def construir_error_generico(secuencia=0):
    cuerpo = json.dumps({"codigo": "ERROR", "descripcion": "Solicitud rechazada"}).encode("utf-8")
    return construir_trama(
        TIPO_ERROR,
        secuencia,
        b"\x00" * TAMANO_IV,
        cuerpo,
        b"\x00" * TAMANO_HMAC,
    )
