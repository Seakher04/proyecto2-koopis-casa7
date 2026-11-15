import json
import unittest
from pathlib import Path

import servidor.comandos as mod_comandos
from servidor.comandos import RUTA_BOVEDA, procesar_comando


class TestComandos(unittest.TestCase):
    def setUp(self) -> None:
        RUTA_BOVEDA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_BOVEDA.write_text("{}", encoding="utf-8")

    def tearDown(self) -> None:
        mod_comandos.RUTA_BOVEDA = RUTA_BOVEDA
        RUTA_BOVEDA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_BOVEDA.write_text("{}", encoding="utf-8")

    def test_creacion_automatica_boveda_si_no_existe(self) -> None:
        if RUTA_BOVEDA.exists():
            RUTA_BOVEDA.unlink()
        self.assertFalse(RUTA_BOVEDA.exists())

        sesion = {"autenticado": True, "perfil": "integrante"}
        tipo, resp = procesar_comando({"comando": "consultar", "clave": ""}, sesion)

        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["datos"], {})
        self.assertTrue(RUTA_BOVEDA.exists())
        self.assertEqual(json.loads(RUTA_BOVEDA.read_text(encoding="utf-8")), {})

    def test_rechazo_no_autenticado(self) -> None:
        sesion = {"autenticado": False, "perfil": "jefe"}
        comandos_prueba = [
            {"comando": "consultar", "clave": ""},
            {"comando": "agregar", "clave": "k1", "valor": "v1"},
            {"comando": "borrar", "clave": "k1"},
            {"comando": "cierre_emergencia"},
        ]
        for payload in comandos_prueba:
            with self.subTest(comando=payload["comando"]):
                tipo, resp = procesar_comando(payload, sesion)
                self.assertEqual(tipo, 0x05)
                self.assertEqual(resp["codigo"], "NO_AUTENTICADO")

    def test_perfil_hacinado_recibe_no_autorizado_en_los_4_comandos(self) -> None:
        sesion = {"autenticado": True, "perfil": "hacinado"}
        comandos_prueba = [
            {"comando": "consultar", "clave": ""},
            {"comando": "agregar", "clave": "k1", "valor": "v1"},
            {"comando": "borrar", "clave": "k1"},
            {"comando": "cierre_emergencia"},
        ]
        for payload in comandos_prueba:
            with self.subTest(comando=payload["comando"]):
                tipo, resp = procesar_comando(payload, sesion)
                self.assertEqual(tipo, 0x05)
                self.assertEqual(resp["codigo"], "NO_AUTORIZADO")

    def test_perfil_integrante_permisos_y_operaciones(self) -> None:
        sesion = {"autenticado": True, "perfil": "integrante"}

        # Agregar elementos
        tipo, resp = procesar_comando(
            {"comando": "agregar", "clave": "api_key", "valor": "12345"}, sesion
        )
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["estado"], "OK")
        self.assertEqual(resp["datos"], {})

        procesar_comando(
            {"comando": "agregar", "clave": "token", "valor": "abcde"}, sesion
        )

        # Consultar clave específica
        tipo, resp = procesar_comando(
            {"comando": "consultar", "clave": "api_key"}, sesion
        )
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["estado"], "OK")
        self.assertEqual(resp["datos"], {"api_key": "12345"})

        # Consultar clave vacía "" (todo el diccionario)
        tipo, resp = procesar_comando({"comando": "consultar", "clave": ""}, sesion)
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["estado"], "OK")
        self.assertEqual(
            resp["datos"],
            {"api_key": "12345", "token": "abcde"},
        )

        # Rechazo en borrar
        tipo, resp = procesar_comando(
            {"comando": "borrar", "clave": "api_key"}, sesion
        )
        self.assertEqual(tipo, 0x05)
        self.assertEqual(resp["codigo"], "NO_AUTORIZADO")

        # Rechazo en cierre_emergencia
        tipo, resp = procesar_comando({"comando": "cierre_emergencia"}, sesion)
        self.assertEqual(tipo, 0x05)
        self.assertEqual(resp["codigo"], "NO_AUTORIZADO")

    def test_perfil_jefe_operaciones_completas_y_cierre_emergencia(self) -> None:
        sesion = {"autenticado": True, "perfil": "jefe", "cerrar_servidor": False}

        # Agregar
        tipo, resp = procesar_comando(
            {"comando": "agregar", "clave": "secreto1", "valor": "val1"}, sesion
        )
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["datos"], {})

        procesar_comando(
            {"comando": "agregar", "clave": "secreto2", "valor": "val2"}, sesion
        )

        # Consultar específica y general
        tipo, resp = procesar_comando(
            {"comando": "consultar", "clave": "secreto1"}, sesion
        )
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["datos"], {"secreto1": "val1"})

        tipo, resp = procesar_comando({"comando": "consultar", "clave": ""}, sesion)
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["datos"], {"secreto1": "val1", "secreto2": "val2"})

        # Borrar
        tipo, resp = procesar_comando(
            {"comando": "borrar", "clave": "secreto1"}, sesion
        )
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["datos"], {})

        tipo, resp = procesar_comando({"comando": "consultar", "clave": ""}, sesion)
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["datos"], {"secreto2": "val2"})

        # Cierre de emergencia
        tipo, resp = procesar_comando({"comando": "cierre_emergencia"}, sesion)
        self.assertEqual(tipo, 0x04)
        self.assertEqual(resp["estado"], "OK")
        self.assertEqual(resp["datos"], {})
        self.assertTrue(sesion["cerrar_servidor"])

        contenido_disco = json.loads(RUTA_BOVEDA.read_text(encoding="utf-8"))
        self.assertEqual(contenido_disco, {})

    def test_errores_solicitud_invalida_y_no_encontrado(self) -> None:
        sesion = {"autenticado": True, "perfil": "jefe"}

        solicitudes_invalidas = [
            {},
            {"comando": "inexistente"},
            {"comando": "consultar"},
            {"comando": "agregar", "clave": "solo_clave"},
            {"comando": "agregar", "valor": "solo_valor"},
            {"comando": "agregar", "clave": "", "valor": "v"},
            {"comando": "borrar"},
            {"comando": "borrar", "clave": ""},
        ]
        for payload in solicitudes_invalidas:
            with self.subTest(payload=payload):
                tipo, resp = procesar_comando(payload, sesion)
                self.assertEqual(tipo, 0x05)
                self.assertEqual(resp["codigo"], "SOLICITUD_INVALIDA")

        # NO_ENCONTRADO en consultar con clave inexistente
        tipo, resp = procesar_comando(
            {"comando": "consultar", "clave": "no_existe"}, sesion
        )
        self.assertEqual(tipo, 0x05)
        self.assertEqual(resp["codigo"], "NO_ENCONTRADO")

        # NO_ENCONTRADO en borrar con clave inexistente
        tipo, resp = procesar_comando(
            {"comando": "borrar", "clave": "no_existe"}, sesion
        )
        self.assertEqual(tipo, 0x05)
        self.assertEqual(resp["codigo"], "NO_ENCONTRADO")


if __name__ == "__main__":
    unittest.main()
