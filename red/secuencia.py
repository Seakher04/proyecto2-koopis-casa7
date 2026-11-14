"""Contadores de secuencia por sesion para evitar repeticion de paquetes."""


class ControlSecuencia:
    def __init__(self, inicio=1):
        self.seq_envio = inicio
        self.seq_esperado = inicio

    def siguiente_envio(self):
        actual = self.seq_envio
        self.seq_envio += 1
        return actual

    def validar_recepcion(self, seq_recibido):
        if seq_recibido != self.seq_esperado:
            return False
        self.seq_esperado += 1
        return True
