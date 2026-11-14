# Proyecto 2: Casa 7 (KOOPIS)

Curso: Redes de Comunicación de Datos (CI-0121)  
Universidad de Costa Rica

## Integrantes y reparto
- Sebastián Sánchez Jiménez (P1): red TCP, framing, secuencia y control de conexiones (`red/`, `servidor/boveda.py`, `cliente/custodio.py`).
- Marina Castro Peralta (P2): Diffie-Hellman, AES-256-CTR y login (`seguridad/handshake.py`, `seguridad/cifrado.py`, `seguridad/login.py`).
- Hermes Josué Rojas Sancho (P3): HMAC-SHA256 y comandos (`seguridad/integridad.py`, `servidor/comandos.py`).

## Estructura

```text
.
├── red/
│   ├── protocolo.py      # Cabecera !IBQ16s, lectura/envio por TCP
│   ├── secuencia.py      # Contadores anti-repeticion
│   └── defensa.py        # Limite de conexiones y bitacora de errores
├── seguridad/
│   ├── handshake.py
│   ├── cifrado.py
│   ├── login.py
│   └── integridad.py
├── servidor/
│   ├── boveda.py         # Servidor TCP en puerto 7777
│   ├── comandos.py
│   └── datos/            # usuarios.txt, secretos.txt y alertas_red.log
├── cliente/
│   └── custodio.py       # Cliente TCP
└── pruebas/
    └── test_framing.py   # Pruebas unitarias de la capa de red
```

## Ejecución

Desde la raíz del proyecto con Python 3:

```bash
# Terminal 1: levantar la Boveda
python3 -m servidor.boveda

# Terminal 2 (prueba local en la misma maquina):
python3 -m cliente.custodio 127.0.0.1 7777

# En laboratorio / red (cambiar por la IP de la maquina que corre la Boveda):
python3 -m cliente.custodio <IP_SERVIDOR> 7777
```

Para correr las pruebas unitarias de red:

```bash
python3 -m unittest -v pruebas/test_framing.py
```
