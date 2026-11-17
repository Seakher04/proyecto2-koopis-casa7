"""Pruebas de integracion para el cliente Custodio contra la Boveda real."""

import io
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cliente.custodio import ClienteCustodio, iniciar_cliente
from red.protocolo import TIPO_ERROR, TIPO_RESPUESTA
from seguridad.login import agregar_usuario, cargar_usuarios
import servidor.boveda as mod_boveda
from servidor.boveda import manejar_cliente
from servidor.comandos import RUTA_BOVEDA

CLAVE_JEFE = "ClavePruebaJefe2026"
CLAVE_INT = "ClavePruebaInt2026"


class TestCustodioIntegracion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.carpeta_usuarios = tempfile.mkdtemp()
        ruta = os.path.join(cls.carpeta_usuarios, "usuarios.txt")
        agregar_usuario(ruta, "jefe", CLAVE_JEFE, "jefe")
        agregar_usuario(ruta, "integrante", CLAVE_INT, "integrante")
        cls.usuarios = cargar_usuarios(ruta)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.carpeta_usuarios, ignore_errors=True)

    def setUp(self):
        mod_boveda._cierre_en_curso = False
        RUTA_BOVEDA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_BOVEDA.write_text("{}", encoding="utf-8")

        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_sock.bind(("127.0.0.1", 0))
        self.srv_sock.listen(5)
        self.puerto = self.srv_sock.getsockname()[1]

        self._detener = False
        self.hilo = threading.Thread(target=self._aceptar, daemon=True)
        self.hilo.start()

    def _aceptar(self):
        while not self._detener:
            try:
                conn, _ = self.srv_sock.accept()
            except OSError:
                break
            manejar_cliente(conn, self.srv_sock, self.usuarios)

    def tearDown(self):
        self._detener = True
        try:
            self.srv_sock.close()
        except OSError:
            pass
        self.hilo.join(timeout=2.0)
        mod_boveda._cierre_en_curso = False
        RUTA_BOVEDA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_BOVEDA.write_text("{}", encoding="utf-8")

    def test_flujo_completo_cliente_custodio(self):
        cli = ClienteCustodio("127.0.0.1", self.puerto)
        try:
            cli.conectar()
            cli.hacer_handshake()

            tipo, resp = cli.iniciar_sesion("integrante", "mala")
            self.assertEqual(tipo, TIPO_ERROR)
            self.assertEqual(resp["codigo"], "CREDENCIALES")

            tipo, resp = cli.iniciar_sesion("integrante", CLAVE_INT)
            self.assertEqual(tipo, TIPO_RESPUESTA)
            self.assertEqual(resp["perfil"], "integrante")

            tipo, resp = cli.enviar_comando({"comando": "agregar", "clave": "nota", "valor": "secreta"})
            self.assertEqual(tipo, TIPO_RESPUESTA)

            tipo, resp = cli.enviar_comando({"comando": "consultar", "clave": "nota"})
            self.assertEqual(tipo, TIPO_RESPUESTA)
            self.assertEqual(resp["datos"], {"nota": "secreta"})

            tipo, resp = cli.enviar_comando({"comando": "borrar", "clave": "nota"})
            self.assertEqual(tipo, TIPO_ERROR)
            self.assertEqual(resp["codigo"], "NO_AUTORIZADO")
        finally:
            cli.cerrar()

    def test_flujo_terminal_interactivo_con_cierre(self):
        entradas = iter([
            "jefe",
            "2", "llave1", "valor1",
            "1", "",
            "3", "llave1",
            "4", "s",
        ])
        salida = io.StringIO()
        with (
            patch("builtins.input", side_effect=lambda _prompt="": next(entradas)),
            patch("getpass.getpass", return_value=CLAVE_JEFE),
            redirect_stdout(salida),
        ):
            iniciar_cliente("127.0.0.1", self.puerto)

        texto = salida.getvalue()
        self.assertIn("Handshake completado", texto)
        self.assertIn("perfil: jefe", texto)
        self.assertIn("llave1: valor1", texto)
        self.assertIn("Boveda cerrada por emergencia", texto)
        self.assertEqual(json.loads(RUTA_BOVEDA.read_text(encoding="utf-8")), {})


if __name__ == "__main__":
    unittest.main()
