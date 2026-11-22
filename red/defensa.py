"""Control de conexiones, limite de errores y registro de anomalias de red."""

import threading
import time
from pathlib import Path

RUTA_LOG_DEFECTO = Path(__file__).resolve().parent.parent / "servidor" / "datos" / "alertas_red.log"
MAX_BYTES_LOG = 512 * 1024


class RegistroDefensivo:
    def __init__(
        self,
        ruta_log=RUTA_LOG_DEFECTO,
        ventana_seg=20.0,
        max_faltas=8,
        bloqueo_seg=15.0,
        demora_base_seg=0.25,
        max_conexiones=32,
        max_por_ip=6,
    ):
        self.ruta_log = Path(ruta_log)
        self.ventana_seg = ventana_seg
        self.max_faltas = max_faltas
        self.bloqueo_seg = bloqueo_seg
        self.demora_base_seg = demora_base_seg
        self.max_conexiones = max_conexiones
        self.max_por_ip = max_por_ip

        self._lock = threading.Lock()
        self._faltas = {}
        self._bloqueados_hasta = {}
        self._conexiones_totales = 0
        self._conexiones_ip = {}

    def adquirir_conexion(self, ip):
        """Verifica bloqueo y limites de concurrencia antes de aceptar un hilo."""
        ahora = time.monotonic()
        with self._lock:
            expira = self._bloqueados_hasta.get(ip, 0.0)
            if ahora < expira:
                return False
            if ip in self._bloqueados_hasta:
                del self._bloqueados_hasta[ip]

            if self._conexiones_totales >= self.max_conexiones:
                self._guardar_log(ip, "limite_global", self._conexiones_totales, "")
                return False

            activas_ip = self._conexiones_ip.get(ip, 0)
            if activas_ip >= self.max_por_ip:
                self._guardar_log(ip, "limite_por_ip", activas_ip, "")
                return False

            self._conexiones_totales += 1
            self._conexiones_ip[ip] = activas_ip + 1
            return True

    def liberar_conexion(self, ip):
        with self._lock:
            if self._conexiones_totales > 0:
                self._conexiones_totales -= 1
            activas_ip = self._conexiones_ip.get(ip, 0)
            if activas_ip <= 1:
                self._conexiones_ip.pop(ip, None)
            else:
                self._conexiones_ip[ip] = activas_ip - 1

    def esta_bloqueada(self, ip):
        ahora = time.monotonic()
        with self._lock:
            expira = self._bloqueados_hasta.get(ip, 0.0)
            if ahora < expira:
                return True
            if ip in self._bloqueados_hasta:
                del self._bloqueados_hasta[ip]
            return False

    def registrar_anomalia(self, ip, motivo, detalle=""):
        """Anota un intento invalido y devuelve una demora corta para frenar escaneos."""
        ahora = time.monotonic()
        with self._lock:
            limite = ahora - self.ventana_seg
            lista = [t for t in self._faltas.get(ip, []) if t >= limite]
            lista.append(ahora)
            self._faltas[ip] = lista

            cantidad = len(lista)
            if cantidad >= self.max_faltas and ip not in self._bloqueados_hasta:
                self._bloqueados_hasta[ip] = ahora + self.bloqueo_seg

            self._guardar_log(ip, motivo, cantidad, detalle)
            return min(self.demora_base_seg * cantidad, 1.5)

    def registrar_evento(self, ip, evento, detalle=""):
        """Anota un evento de auditoria (login, comandos, conexiones) sin sumar faltas."""
        with self._lock:
            self._escribir_linea("INFO", ip, evento, detalle)

    def _sanitizar(self, texto, max_len=160):
        limpio = str(texto).replace("\r", " ").replace("\n", " ").strip()
        if len(limpio) > max_len:
            return limpio[:max_len] + "..."
        return limpio

    def _rotar_si_necesario(self):
        self.ruta_log.parent.mkdir(parents=True, exist_ok=True)
        # Evita que un flood de paquetes malos llene el disco
        if self.ruta_log.exists() and self.ruta_log.stat().st_size > MAX_BYTES_LOG:
            respaldo = self.ruta_log.with_suffix(".log.1")
            self.ruta_log.replace(respaldo)

    def _escribir_linea(self, nivel, ip, evento, detalle="", conteo=None):
        self._rotar_si_necesario()
        hora = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        linea = f"[{hora} UTC] nivel={nivel} ip={ip} evento={evento}"
        if conteo is not None:
            linea += f" conteo={conteo}"
        if detalle:
            linea += f" detalle={self._sanitizar(detalle)}"
        with self.ruta_log.open("a", encoding="utf-8") as f:
            f.write(linea + "\n")

    def _guardar_log(self, ip, motivo, conteo, detalle):
        self._escribir_linea("ALERTA", ip, motivo, detalle=detalle, conteo=conteo)
