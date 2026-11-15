import hashlib
import hmac

TIPO_HANDSHAKE = 0x01
TIPO_COMANDO = 0x03
LONGITUD_HMAC = 32
OFFSET_BLOQUE_CMD = 24


def calcular_hmac(cabecera: bytes, payload_cifrado: bytes, k_int: bytes) -> bytes:
    """Calcula la firma HMAC-SHA256 sobre la cabecera y el bloque de payload aplicable."""
    tipo = cabecera[4]

    if tipo == TIPO_HANDSHAKE:
        return b"\x00" * LONGITUD_HMAC

    if tipo == TIPO_COMANDO:
        segmento_payload = payload_cifrado[OFFSET_BLOQUE_CMD:]
    else:
        segmento_payload = payload_cifrado

    mensaje = cabecera + segmento_payload
    return hmac.new(k_int, mensaje, hashlib.sha256).digest()


def verificar_hmac(
    cabecera: bytes,
    payload_cifrado: bytes,
    hmac_recibido: bytes,
    k_int: bytes,
) -> bool:
    """Verifica la firma HMAC-SHA256 recibida en tiempo constante."""
    hmac_esperado = calcular_hmac(cabecera, payload_cifrado, k_int)
    return hmac.compare_digest(hmac_esperado, hmac_recibido)
