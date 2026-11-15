import struct
import unittest

from seguridad.integridad import calcular_hmac, verificar_hmac


def construir_cabecera(longitud: int, tipo: int, nonce: int = 1, iv: bytes = b"I" * 16) -> bytes:
    return struct.pack("!IBQ16s", longitud, tipo, nonce, iv)


class TestIntegridad(unittest.TestCase):
    def setUp(self) -> None:
        self.k_int = b"K" * 32

    def test_handshake_genera_ceros_y_valida_true(self) -> None:
        payload = b'{"A": 123456}'
        cabecera = construir_cabecera(len(payload), 0x01)

        firma = calcular_hmac(cabecera, payload, b"")
        self.assertEqual(firma, b"\x00" * 32)
        self.assertEqual(len(firma), 32)
        self.assertTrue(verificar_hmac(cabecera, payload, firma, b""))

    def test_mensajes_estandar_alterar_cabecera_o_payload_invalida_hmac(self) -> None:
        payload = bytes(range(48))

        for tipo in (0x02, 0x04, 0x05):
            with self.subTest(tipo=hex(tipo)):
                cabecera = construir_cabecera(len(payload), tipo)
                firma = calcular_hmac(cabecera, payload, self.k_int)
                self.assertTrue(verificar_hmac(cabecera, payload, firma, self.k_int))

                for i in range(len(cabecera)):
                    cabecera_alterada = bytearray(cabecera)
                    cabecera_alterada[i] ^= 0x10
                    self.assertFalse(
                        verificar_hmac(bytes(cabecera_alterada), payload, firma, self.k_int),
                        f"Alterar byte {i} de la cabecera en tipo {hex(tipo)} debio invalidar el HMAC",
                    )

                for i in range(len(payload)):
                    payload_alterado = bytearray(payload)
                    payload_alterado[i] ^= 0x01
                    self.assertFalse(
                        verificar_hmac(cabecera, bytes(payload_alterado), firma, self.k_int),
                        f"Alterar byte {i} del payload en tipo {hex(tipo)} debio invalidar el HMAC",
                    )

if __name__ == "__main__":
    unittest.main()
