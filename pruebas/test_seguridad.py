"""Pruebas de los modulos de seguridad (puntos 5, 6 y 7).

Correr desde la raiz del repo: python -m unittest pruebas.test_seguridad
Los usuarios de prueba se crean en una carpeta temporal del sistema, no en el repo.
"""

import json
import os
import secrets
import statistics
import tempfile
import time
import unittest

from seguridad import cifrado, handshake, login


def es_primo(n, rondas=20):
    """Prueba de Miller-Rabin."""
    if n < 4:
        return n in (2, 3)
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(rondas):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _bytes(objeto):
    return json.dumps(objeto).encode("utf-8")


def handshake_completo():
    """Corre el handshake de los dos lados y devuelve (claves cliente, claves servidor)."""
    a, hola = handshake.iniciar_handshake()
    b_hex, k_cif_srv, k_int_srv = handshake.procesar_handshake(_bytes(hola))
    k_cif_cli, k_int_cli = handshake.terminar_handshake(a, _bytes({"grupo": 14, "B": b_hex}))
    return (k_cif_cli, k_int_cli), (k_cif_srv, k_int_srv)


class PruebasHandshake(unittest.TestCase):

    def test_p_es_primo_seguro(self):
        self.assertEqual(handshake.P.bit_length(), 2048)
        self.assertTrue(es_primo(handshake.P))
        self.assertTrue(es_primo((handshake.P - 1) // 2))

    def test_los_dos_lados_llegan_a_las_mismas_claves(self):
        cliente, servidor = handshake_completo()
        self.assertEqual(cliente, servidor)

    def test_claves_de_32_bytes_y_distintas(self):
        (k_cif, k_int), _ = handshake_completo()
        self.assertEqual(len(k_cif), 32)
        self.assertEqual(len(k_int), 32)
        self.assertNotEqual(k_cif, k_int)

    def test_cada_conexion_tiene_claves_nuevas(self):
        primera, _ = handshake_completo()
        segunda, _ = handshake_completo()
        self.assertNotEqual(primera, segunda)

    def test_rechaza_A_fuera_de_rango(self):
        for valor in (0, 1, handshake.P - 1, handshake.P, handshake.P + 5):
            with self.subTest(valor=valor):
                self.assertIsNone(
                    handshake.procesar_handshake(_bytes({"version": 1, "grupo": 14, "A": format(valor, "x")}))
                )

    def test_rechaza_A_mal_formado(self):
        for valor in ("", "zz", "-5", "0x10", " 10", "f" * 600, 123, None, ["10"]):
            with self.subTest(valor=valor):
                self.assertIsNone(
                    handshake.procesar_handshake(_bytes({"version": 1, "grupo": 14, "A": valor}))
                )

    def test_rechaza_version_o_grupo_distintos(self):
        _, hola = handshake.iniciar_handshake()
        for cambio in ({"version": 2}, {"grupo": 5}, {"version": True}, {"grupo": 14.0}):
            with self.subTest(cambio=cambio):
                self.assertIsNone(handshake.procesar_handshake(_bytes({**hola, **cambio})))

    def test_rechaza_bytes_que_no_son_json_objeto(self):
        for crudo in (b"", b"no es json", b"[1, 2, 3]", b"\xff\xfe", b"\"hola\""):
            with self.subTest(crudo=crudo):
                self.assertIsNone(handshake.procesar_handshake(crudo))

    def test_cliente_rechaza_B_fuera_de_rango(self):
        a, _ = handshake.iniciar_handshake()
        for valor in (1, handshake.P - 1):
            with self.subTest(valor=valor):
                self.assertIsNone(handshake.terminar_handshake(a, _bytes({"grupo": 14, "B": format(valor, "x")})))

    def test_tamano_del_0x01(self):
        _, hola = handshake.iniciar_handshake()
        b_hex, _, _ = handshake.procesar_handshake(_bytes(hola))
        self.assertLess(len(_bytes(hola)), 600)
        self.assertLess(len(_bytes({"grupo": 14, "B": b_hex})), 600)


class PruebasCifrado(unittest.TestCase):

    def setUp(self):
        (self.k_cif, _), _ = handshake_completo()

    def test_ida_y_vuelta(self):
        datos = "Plano del ala norte ñ á".encode("utf-8")
        iv = cifrado.nuevo_iv()
        cif = cifrado.cifrar(datos, self.k_cif, iv)
        self.assertEqual(cifrado.descifrar(cif, self.k_cif, iv), datos)

    def test_mide_lo_mismo_que_el_claro(self):
        datos = b"x" * 547
        cif = cifrado.cifrar(datos, self.k_cif, cifrado.nuevo_iv())
        self.assertEqual(len(cif), len(datos))

    def test_iv_de_16_bytes(self):
        self.assertEqual(len(cifrado.nuevo_iv()), 16)

    def test_la_clave_no_se_ve_en_el_cifrado(self):
        clave = b"MiClaveSuperSecreta2026"
        cif = cifrado.cifrar(clave, self.k_cif, cifrado.nuevo_iv())
        self.assertNotIn(clave, cif)

    def test_otra_clave_da_otro_texto(self):
        datos = b"{\"estado\": \"OK\"}"
        iv = cifrado.nuevo_iv()
        cif = cifrado.cifrar(datos, self.k_cif, iv)
        self.assertNotEqual(cifrado.descifrar(cif, secrets.token_bytes(32), iv), datos)

    def test_vector_oficial_nist(self):
        # NIST SP 800-38A, F.5.5 (CTR-AES256), dos primeros bloques
        clave = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        contador = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        claro = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51")
        esperado = bytes.fromhex("601ec313775789a5b7a7f504bbf3d228" "f443e3ca4d62b59aca84e990cacaf5c5")
        self.assertEqual(cifrado.cifrar(claro, clave, contador), esperado)


class PruebasLogin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.carpeta = tempfile.TemporaryDirectory()
        cls.ruta = os.path.join(cls.carpeta.name, "usuarios.txt")
        cls.claves = {}
        for usuario, perfil in (("ana", "jefe"), ("beto", "integrante"), ("asilo", "hacinado")):
            cls.claves[usuario] = secrets.token_urlsafe(12)
            login.agregar_usuario(cls.ruta, usuario, cls.claves[usuario], perfil)
        cls.usuarios = login.cargar_usuarios(cls.ruta)

    @classmethod
    def tearDownClass(cls):
        cls.carpeta.cleanup()

    def test_login_correcto_da_el_perfil_del_archivo(self):
        self.assertEqual(login.verificar_credenciales(self.usuarios, "ana", self.claves["ana"]), "jefe")
        self.assertEqual(login.verificar_credenciales(self.usuarios, "asilo", self.claves["asilo"]), "hacinado")

    def test_clave_mala_o_usuario_inexistente_da_none(self):
        self.assertIsNone(login.verificar_credenciales(self.usuarios, "ana", "mala"))
        self.assertIsNone(login.verificar_credenciales(self.usuarios, "zoe", "algo"))

    def test_payloads_raros_no_revientan(self):
        for usuario, clave in ((5, "x"), ("ana", None), ("a" * 1000, "x"), ("ana", "x" * 100000), (None, None)):
            with self.subTest(usuario=usuario):
                self.assertIsNone(login.verificar_credenciales(self.usuarios, usuario, clave))

    def test_tarda_lo_mismo_si_el_usuario_no_existe(self):
        def medir(usuario):
            inicio = time.perf_counter()
            login.verificar_credenciales(self.usuarios, usuario, "clave-mala")
            return time.perf_counter() - inicio
        no_existe = statistics.median(medir("zoe") for _ in range(3))
        existe = statistics.median(medir("ana") for _ in range(3))
        self.assertLess(max(no_existe, existe) / min(no_existe, existe), 2)


class PruebasArchivoUsuarios(unittest.TestCase):

    def setUp(self):
        self.carpeta = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.carpeta.name, "usuarios.txt")

    def tearDown(self):
        self.carpeta.cleanup()

    def test_el_archivo_no_guarda_la_clave(self):
        login.agregar_usuario(self.ruta, "ana", "ClaveDePrueba2026", "jefe")
        with open(self.ruta, encoding="utf-8") as archivo:
            self.assertNotIn("ClaveDePrueba2026", archivo.read())

    def test_misma_clave_da_hash_distinto(self):
        login.agregar_usuario(self.ruta, "ana", "ClaveDePrueba2026", "jefe")
        login.agregar_usuario(self.ruta, "beto", "ClaveDePrueba2026", "integrante")
        usuarios = login.cargar_usuarios(self.ruta)
        self.assertNotEqual(usuarios["ana"][2], usuarios["beto"][2])

    def test_datos_invalidos_al_agregar(self):
        login.agregar_usuario(self.ruta, "ana", "ClaveDePrueba2026", "jefe")
        casos = (("ana", "OtraClaveLarga1", "jefe"),     # repetido
                 ("bea", "OtraClaveLarga1", "admin"),    # perfil que no existe
                 ("be:a", "OtraClaveLarga1", "jefe"),    # dos puntos rompen el formato
                 ("bea", "corta", "jefe"))               # clave debil
        for usuario, clave, perfil in casos:
            with self.subTest(usuario=usuario, perfil=perfil):
                with self.assertRaises(ValueError):
                    login.agregar_usuario(self.ruta, usuario, clave, perfil)

    def test_linea_rota_en_el_archivo(self):
        with open(self.ruta, "w", encoding="utf-8") as archivo:
            archivo.write("ana:jefe:abcd\n")
        with self.assertRaises(ValueError):
            login.cargar_usuarios(self.ruta)


class PruebaFlujoCompleto(unittest.TestCase):
    """Handshake, login cifrado y respuesta cifrada, de punta a punta y sin sockets."""

    def test_flujo(self):
        carpeta = tempfile.TemporaryDirectory()
        ruta = os.path.join(carpeta.name, "usuarios.txt")
        login.agregar_usuario(ruta, "ana", "ClaveDePrueba2026", "jefe")
        usuarios = login.cargar_usuarios(ruta)

        # Handshake (0x01 en claro)
        a, hola = handshake.iniciar_handshake()
        b_hex, k_cif_srv, _ = handshake.procesar_handshake(_bytes(hola))
        k_cif_cli, _ = handshake.terminar_handshake(a, _bytes({"grupo": 14, "B": b_hex}))

        # Login (0x02 cifrado): el cliente cifra, el servidor descifra y valida
        iv = cifrado.nuevo_iv()
        cif = cifrado.cifrar(_bytes({"usuario": "ana", "clave": "ClaveDePrueba2026"}), k_cif_cli, iv)
        payload = json.loads(cifrado.descifrar(cif, k_cif_srv, iv).decode("utf-8"))
        self.assertEqual(login.verificar_credenciales(usuarios, payload["usuario"], payload["clave"]), "jefe")
        carpeta.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
