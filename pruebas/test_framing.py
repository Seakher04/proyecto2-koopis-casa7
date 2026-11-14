"""Pruebas unitarias locales para la capa de red (P1)."""

import socket
import tempfile
import time
import unittest
from pathlib import Path

from red.defensa import RegistroDefensivo
from red.protocolo import (
    TAMANO_HMAC,
    TAMANO_IV,
    TAMANO_MAX_PAYLOAD,
    TIPO_COMANDO,
    ErrorProtocolo,
    construir_trama,
    enviar_trama,
    recibir_trama,
)
from red.secuencia import ControlSecuencia


class TestProtocoloRed(unittest.TestCase):
    def test_envio_y_recepcion_fragmentada(self):
        cli, srv = socket.socketpair()
        try:
            iv = b"\x01" * TAMANO_IV
            payload = b'{"accion": "consultar"}'
            hmac_tag = b"\xaa" * TAMANO_HMAC
            trama = construir_trama(TIPO_COMANDO, 1, iv, payload, hmac_tag)

            for i in range(0, len(trama), 5):
                cli.sendall(trama[i : i + 5])

            tipo, seq, iv_rec, pay_rec, tag_rec = recibir_trama(srv)
            self.assertEqual(tipo, TIPO_COMANDO)
            self.assertEqual(seq, 1)
            self.assertEqual(iv_rec, iv)
            self.assertEqual(pay_rec, payload)
            self.assertEqual(tag_rec, hmac_tag)
        finally:
            cli.close()
            srv.close()

    def test_rechaza_payload_mayor_al_limite(self):
        cli, srv = socket.socketpair()
        try:
            cabecera_mal = (
                (TAMANO_MAX_PAYLOAD + 1).to_bytes(4, "big")
                + bytes([TIPO_COMANDO])
                + (1).to_bytes(8, "big")
                + (b"\x00" * TAMANO_IV)
            )
            cli.sendall(cabecera_mal)
            with self.assertRaises(ErrorProtocolo):
                recibir_trama(srv)
        finally:
            cli.close()
            srv.close()

    def test_corta_trama_incompleta_por_timeout(self):
        cli, srv = socket.socketpair()
        try:
            srv.settimeout(2.0)
            cli.sendall(b"\x00\x00\x00\x10\x03")  # envia solo 5 bytes de cabecera y se detiene
            with self.assertRaises(ErrorProtocolo):
                recibir_trama(srv, timeout_trama=0.1)
        finally:
            cli.close()
            srv.close()

    def test_timeout_inactivo_sin_bytes(self):
        cli, srv = socket.socketpair()
        try:
            srv.settimeout(0.05)
            with self.assertRaises(TimeoutError):
                recibir_trama(srv, timeout_trama=0.5)
        finally:
            cli.close()
            srv.close()

    def test_enviar_trama_helper(self):
        cli, srv = socket.socketpair()
        try:
            enviar_trama(cli, TIPO_COMANDO, 4, b"\x02" * TAMANO_IV, b"{}", b"\x03" * TAMANO_HMAC)
            tipo, seq, _, pay, _ = recibir_trama(srv)
            self.assertEqual((tipo, seq, pay), (TIPO_COMANDO, 4, b"{}"))
        finally:
            cli.close()
            srv.close()


class TestSecuencia(unittest.TestCase):
    def test_secuencia_estricta(self):
        ctrl = ControlSecuencia()
        self.assertEqual(ctrl.siguiente_envio(), 1)
        self.assertEqual(ctrl.siguiente_envio(), 2)
        self.assertTrue(ctrl.validar_recepcion(1))
        self.assertFalse(ctrl.validar_recepcion(1))
        self.assertFalse(ctrl.validar_recepcion(3))
        self.assertTrue(ctrl.validar_recepcion(2))


class TestDefensa(unittest.TestCase):
    def test_limites_conexion_y_enfriamiento(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "alertas.log"
            reg = RegistroDefensivo(
                ruta_log=log_path,
                ventana_seg=5.0,
                max_faltas=3,
                bloqueo_seg=0.15,
                max_conexiones=3,
                max_por_ip=2,
            )
            self.assertTrue(reg.adquirir_conexion("10.0.0.5"))
            self.assertTrue(reg.adquirir_conexion("10.0.0.5"))
            self.assertFalse(reg.adquirir_conexion("10.0.0.5"))  # tope por IP
            self.assertTrue(reg.adquirir_conexion("10.0.0.6"))
            self.assertFalse(reg.adquirir_conexion("10.0.0.7"))  # tope global

            reg.liberar_conexion("10.0.0.5")
            reg.liberar_conexion("10.0.0.5")
            reg.liberar_conexion("10.0.0.6")

            reg.registrar_anomalia("10.0.0.8", "trama_invalida")
            reg.registrar_anomalia("10.0.0.8", "trama_invalida")
            self.assertFalse(reg.esta_bloqueada("10.0.0.8"))
            reg.registrar_anomalia("10.0.0.8", "secuencia_invalida")
            self.assertTrue(reg.esta_bloqueada("10.0.0.8"))
            self.assertFalse(reg.adquirir_conexion("10.0.0.8"))

            time.sleep(0.2)
            self.assertFalse(reg.esta_bloqueada("10.0.0.8"))
            self.assertTrue(reg.adquirir_conexion("10.0.0.8"))
            reg.liberar_conexion("10.0.0.8")
            self.assertTrue(log_path.exists())


if __name__ == "__main__":
    unittest.main()
