"""Punto 7: confidencialidad. Cifrado AES-256-CTR del payload."""

import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAMANO_IV = 16


def nuevo_iv():
    """IV de 16 bytes para un mensaje. La regla del IV vive solo aqui."""
    return secrets.token_bytes(TAMANO_IV)


def cifrar(datos, k_cif, iv):
    """AES-256 en modo contador: cifra los bytes del payload con el IV dado."""
    cifrador = Cipher(algorithms.AES(k_cif), modes.CTR(iv)).encryptor()
    return cifrador.update(datos) + cifrador.finalize()


def descifrar(datos_cifrados, k_cif, iv):
    """AES-256 en modo contador: descifra. Es la misma operacion que cifrar."""
    descifrador = Cipher(algorithms.AES(k_cif), modes.CTR(iv)).decryptor()
    return descifrador.update(datos_cifrados) + descifrador.finalize()
