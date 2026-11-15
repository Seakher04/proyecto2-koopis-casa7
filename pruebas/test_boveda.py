import json
import os
import secrets
import socket
import threading
import unittest

from seguridad.integridad import calcular_hmac, verificar_hmac
from servidor.boveda import (
    DH_G,
    DH_P,
    TIPO_COMANDO,
    TIPO_ERROR,
    TIPO_HANDSHAKE,
    TIPO_LOGIN,
    TIPO_RESPUESTA_OK,
    _cifrar,
    _construir_cabecera,
    _derivar_claves,
    _descifrar,
    _enviar_paquete,
    _leer_paquete,
    manejar_cliente,
)
from servidor.comandos import RUTA_BOVEDA


class ClientePrueba:
    """Cliente auxiliar para pruebas de integración contra servidor/boveda.py."""

    def __init__(self, host: str, puerto: int) -> None:
        self.sock = socket.create_connection((host, puerto), timeout=3.0)
        self.nonce = 0
        self.k_cif: bytes | None = None
        self.k_int: bytes | None = None

    def cerrar(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def realizar_handshake(self) -> tuple[int, dict]:
        priv_a = secrets.randbelow(DH_P - 3) + 2
        pub_a = pow(DH_G, priv_a, DH_P)

        self.nonce += 1
        _enviar_paquete(
            self.sock,
            TIPO_HANDSHAKE,
            self.nonce,
            {"version": 1, "grupo": 14, "A": format(pub_a, "x")},
            None,
            None,
        )

        paquete = _leer_paquete(self.sock)
        if paquete is None:
            raise ConnectionError("El servidor cerró la conexión durante el handshake")

        cabecera, tipo, _nonce_srv, _iv, payload_bytes, hmac_rec = paquete
        assert verificar_hmac(cabecera, payload_bytes, hmac_rec, b"")
        datos = json.loads(payload_bytes.decode("utf-8"))

        pub_b = int(datos["B"], 16)
        secreto = pow(pub_b, priv_a, DH_P)
        self.k_cif, self.k_int = _derivar_claves(secreto)
        return tipo, datos

    def enviar_cifrado(
        self,
        tipo: int,
        payload_dict: dict,
        nonce_override: int | None = None,
        alterar_hmac: bool = False,
    ) -> None:
        assert self.k_cif is not None and self.k_int is not None
        if nonce_override is not None:
            nonce_actual = nonce_override
        else:
            self.nonce += 1
            nonce_actual = self.nonce

        iv = os.urandom(16)
        payload_bytes = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
        payload_cifrado = _cifrar(payload_bytes, self.k_cif, iv)
        cabecera = _construir_cabecera(len(payload_cifrado), tipo, nonce_actual, iv)
        firma = bytearray(calcular_hmac(cabecera, payload_cifrado, self.k_int))
        if alterar_hmac:
            firma[0] ^= 0xFF
        self.sock.sendall(cabecera + payload_cifrado + bytes(firma))

    def recibir_cifrado(self) -> tuple[int, dict] | None:
        paquete = _leer_paquete(self.sock)
        if paquete is None:
            return None
        assert self.k_cif is not None and self.k_int is not None
        cabecera, tipo, _nonce_srv, iv, payload_cifrado, hmac_rec = paquete
        assert verificar_hmac(cabecera, payload_cifrado, hmac_rec, self.k_int)
        texto_plano = _descifrar(payload_cifrado, self.k_cif, iv)
        return tipo, json.loads(texto_plano.decode("utf-8"))


class TestBovedaIntegracion(unittest.TestCase):
    def setUp(self) -> None:
        RUTA_BOVEDA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_BOVEDA.write_text("{}", encoding="utf-8")

        self.servidor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.servidor_sock.bind(("127.0.0.1", 0))
        self.servidor_sock.listen(5)
        self.puerto = self.servidor_sock.getsockname()[1]

        self._detener = False
        self.hilo_servidor = threading.Thread(target=self._bucle_servidor, daemon=True)
        self.hilo_servidor.start()

    def _bucle_servidor(self) -> None:
        while not self._detener:
            try:
                conn, _ = self.servidor_sock.accept()
            except OSError:
                break
            manejar_cliente(conn, self.servidor_sock)

    def tearDown(self) -> None:
        self._detener = True
        try:
            self.servidor_sock.close()
        except OSError:
            pass
        self.hilo_servidor.join(timeout=2.0)
        RUTA_BOVEDA.parent.mkdir(parents=True, exist_ok=True)
        RUTA_BOVEDA.write_text("{}", encoding="utf-8")

    def test_enviar_0x03_antes_de_0x01_cierra_conexion_sin_respuesta(self) -> None:
        cliente = ClientePrueba("127.0.0.1", self.puerto)
        try:
            iv = b"\x00" * 16
            payload = b'{"comando": "consultar", "clave": ""}'
            cabecera = _construir_cabecera(len(payload), TIPO_COMANDO, 1, iv)
            firma = b"\x00" * 32
            cliente.sock.sendall(cabecera + payload + firma)

            respuesta = _leer_paquete(cliente.sock)
            self.assertIsNone(respuesta)
        finally:
            cliente.cerrar()

    def test_handshake_nonce_o_iv_invalido_cierra_conexion_sin_respuesta(self) -> None:
        priv_a = secrets.randbelow(DH_P - 3) + 2
        pub_a = pow(DH_G, priv_a, DH_P)
        payload = json.dumps(
            {"version": 1, "grupo": 14, "A": format(pub_a, "x")}
        ).encode("utf-8")
        firma = b"\x00" * 32

        # Caso 1: nonce != 1
        cliente1 = ClientePrueba("127.0.0.1", self.puerto)
        try:
            cabecera_nonce_mal = _construir_cabecera(
                len(payload), TIPO_HANDSHAKE, 2, b"\x00" * 16
            )
            cliente1.sock.sendall(cabecera_nonce_mal + payload + firma)
            self.assertIsNone(_leer_paquete(cliente1.sock))
        finally:
            cliente1.cerrar()

        # Caso 2: iv != 16 bytes en cero
        cliente2 = ClientePrueba("127.0.0.1", self.puerto)
        try:
            cabecera_iv_mal = _construir_cabecera(
                len(payload), TIPO_HANDSHAKE, 1, b"\x01" + b"\x00" * 15
            )
            cliente2.sock.sendall(cabecera_iv_mal + payload + firma)
            self.assertIsNone(_leer_paquete(cliente2.sock))
        finally:
            cliente2.cerrar()

    def test_doble_login_0x02_devuelve_error_sesion_sin_cerrar(self) -> None:
        cliente = ClientePrueba("127.0.0.1", self.puerto)
        try:
            cliente.realizar_handshake()

            # Primer login exitoso
            cliente.enviar_cifrado(
                TIPO_LOGIN, {"usuario": "integrante", "password": "int123"}
            )
            res1 = cliente.recibir_cifrado()
            self.assertIsNotNone(res1)
            if res1 is None:
                self.fail("No se recibió respuesta para el primer login")
            tipo1, datos1 = res1
            self.assertEqual(tipo1, TIPO_RESPUESTA_OK)
            self.assertEqual(datos1["perfil"], "integrante")

            # Segundo login en la misma sesión -> 0x05 SESION sin desconectar
            cliente.enviar_cifrado(
                TIPO_LOGIN, {"usuario": "integrante", "password": "int123"}
            )
            res2 = cliente.recibir_cifrado()
            self.assertIsNotNone(res2)
            if res2 is None:
                self.fail("No se recibió respuesta para el segundo login")
            tipo2, datos2 = res2
            self.assertEqual(tipo2, TIPO_ERROR)
            self.assertEqual(datos2["codigo"], "SESION")

            # Verificar que la conexión sigue activa ejecutando un comando
            cliente.enviar_cifrado(
                TIPO_COMANDO, {"comando": "consultar", "clave": ""}
            )
            res3 = cliente.recibir_cifrado()
            self.assertIsNotNone(res3)
            if res3 is None:
                self.fail("No se recibió respuesta para el comando")
            tipo3, datos3 = res3
            self.assertEqual(tipo3, TIPO_RESPUESTA_OK)
            self.assertEqual(datos3["datos"], {})
        finally:
            cliente.cerrar()

    def test_tres_intentos_fallidos_de_login_cierran_conexion(self) -> None:
        cliente = ClientePrueba("127.0.0.1", self.puerto)
        try:
            cliente.realizar_handshake()

            for intento in range(1, 4):
                cliente.enviar_cifrado(
                    TIPO_LOGIN, {"usuario": "jefe", "password": f"erronea_{intento}"}
                )
                res = cliente.recibir_cifrado()
                if res is None:
                    self.fail("No se recibió respuesta del servidor")
                tipo, datos = res
                self.assertEqual(tipo, TIPO_ERROR)
                self.assertEqual(datos["codigo"], "CREDENCIALES")

            # Tras el 3er intento fallido, el servidor debe haber cerrado el socket
            paquete_extra = _leer_paquete(cliente.sock)
            self.assertIsNone(paquete_extra)
        finally:
            cliente.cerrar()

    def test_falla_de_nonce_devuelve_0x05_y_cierra_conexion(self) -> None:
        cliente = ClientePrueba("127.0.0.1", self.puerto)
        try:
            cliente.realizar_handshake()

            # El handshake usó nonce=1; enviamos nonce=99 en lugar de 2
            cliente.enviar_cifrado(
                TIPO_LOGIN,
                {"usuario": "jefe", "password": "jefe123"},
                nonce_override=99,
            )
            res = cliente.recibir_cifrado()
            if res is None:
                self.fail("No se recibió respuesta del servidor")
            tipo, _datos = res
            self.assertEqual(tipo, TIPO_ERROR)

            self.assertIsNone(_leer_paquete(cliente.sock))
        finally:
            cliente.cerrar()

    def test_falla_de_hmac_devuelve_0x05_y_cierra_conexion(self) -> None:
        cliente = ClientePrueba("127.0.0.1", self.puerto)
        try:
            cliente.realizar_handshake()

            cliente.enviar_cifrado(
                TIPO_LOGIN,
                {"usuario": "jefe", "password": "jefe123"},
                alterar_hmac=True,
            )
            res = cliente.recibir_cifrado()
            if res is None:
                self.fail("No se recibió respuesta del servidor")
            tipo, _datos = res
            self.assertEqual(tipo, TIPO_ERROR)

            self.assertIsNone(_leer_paquete(cliente.sock))
        finally:
            cliente.cerrar()

    def test_flujo_completo_handshake_login_comandos_y_cierre_emergencia(self) -> None:
        cliente = ClientePrueba("127.0.0.1", self.puerto)
        try:
            # 1. Handshake 0x01
            tipo_hs, datos_hs = cliente.realizar_handshake()
            self.assertEqual(tipo_hs, TIPO_HANDSHAKE)
            self.assertEqual(datos_hs.get("grupo"), 14)
            self.assertIn("B", datos_hs)
            self.assertIsInstance(datos_hs["B"], str)
            self.assertFalse(datos_hs["B"].lower().startswith("0x"))

            # 2. Login 0x02 como jefe
            cliente.enviar_cifrado(
                TIPO_LOGIN, {"usuario": "jefe", "password": "jefe123"}
            )
            res_login = cliente.recibir_cifrado()
            if res_login is None:
                self.fail("No se recibió respuesta del servidor")
            tipo_login, datos_login = res_login
            self.assertEqual(tipo_login, TIPO_RESPUESTA_OK)
            self.assertEqual(datos_login["estado"], "OK")
            self.assertEqual(datos_login["perfil"], "jefe")

            # 3. Comandos 0x03: agregar y consultar
            cliente.enviar_cifrado(
                TIPO_COMANDO,
                {"comando": "agregar", "clave": "codigo_nuclear", "valor": "998877"},
            )
            res_add = cliente.recibir_cifrado()
            if res_add is None:
                self.fail("No se recibió respuesta al agregar la clave")
            self.assertEqual(res_add[0], TIPO_RESPUESTA_OK)

            cliente.enviar_cifrado(
                TIPO_COMANDO,
                {"comando": "consultar", "clave": "codigo_nuclear"},
            )
            res_get = cliente.recibir_cifrado()
            if res_get is None:
                self.fail("No se recibió respuesta al consultar la clave")
            self.assertEqual(res_get[0], TIPO_RESPUESTA_OK)
            self.assertEqual(res_get[1]["datos"], {"codigo_nuclear": "998877"})

            # 4. Cierre de emergencia
            cliente.enviar_cifrado(
                TIPO_COMANDO,
                {"comando": "cierre_emergencia"},
            )
            res_cierre = cliente.recibir_cifrado()
            if res_cierre is None:
                self.fail("No se recibió respuesta al cierre de emergencia")
            self.assertEqual(res_cierre[0], TIPO_RESPUESTA_OK)
            self.assertEqual(res_cierre[1]["estado"], "OK")

            # El servidor debe haber cerrado la conexión, vaciado boveda.json y terminado su bucle
            self.assertIsNone(_leer_paquete(cliente.sock))
            self.hilo_servidor.join(timeout=2.0)
            self.assertFalse(self.hilo_servidor.is_alive())
            self.assertEqual(
                json.loads(RUTA_BOVEDA.read_text(encoding="utf-8")),
                {},
            )
        finally:
            cliente.cerrar()


if __name__ == "__main__":
    unittest.main()
