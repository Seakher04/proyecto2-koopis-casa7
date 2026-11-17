# Proyecto 2: Casa 7 (KOOPIS)

Curso: Redes de Comunicación de Datos (CI-0121)  
Universidad de Costa Rica

## Integrantes y reparto
- **Sebastián Sánchez Jiménez (P1)**: capa de red TCP, framing, secuencia y control de conexiones (`red/`, `cliente/custodio.py`).
- **Marina Castro Peralta (P2)**: handshake Diffie-Hellman, cifrado AES-256-CTR y login seguro (`seguridad/handshake.py`, `seguridad/cifrado.py`, `seguridad/login.py`).
- **Hermes Josué Rojas Sancho (P3)**: integridad HMAC-SHA256, comandos y servidor principal de la Bóveda (`seguridad/integridad.py`, `servidor/comandos.py`, `servidor/boveda.py`).

## Estructura

```text
.
├── red/
│   ├── protocolo.py      # Cabecera !IBQ16s, lectura/envío por TCP
│   ├── secuencia.py      # Contadores anti-repetición
│   └── defensa.py        # Límite de conexiones y bitácora de eventos
├── seguridad/
│   ├── handshake.py      # Diffie-Hellman (Grupo 14) y derivación de claves
│   ├── cifrado.py        # Cifrado AES-256-CTR
│   ├── login.py          # Gestión y verificación PBKDF2-HMAC-SHA256
│   └── integridad.py     # Cálculo y verificación HMAC-SHA256
├── servidor/
│   ├── boveda.py         # Servidor TCP concurrente en puerto 7777
│   ├── comandos.py       # Procesamiento de comandos y persistencia JSON
│   └── datos/            # usuarios.txt, boveda.json y alertas_red.log
├── cliente/
│   └── custodio.py       # Cliente TCP
└── pruebas/
    ├── test_framing.py
    ├── test_seguridad.py
    ├── test_integridad.py
    ├── test_comandos.py
    └── test_boveda.py
```

## Requisitos e instalación

Requiere Python 3 y la dependencia declarada en `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Ejecución

Desde la raíz del proyecto:

### 1. Crear usuarios de la Bóveda

La Bóveda requiere que `servidor/datos/usuarios.txt` exista y tenga al menos un usuario antes de iniciar. Perfiles válidos: `jefe`, `integrante` y `hacinado`.

```bash
python3 -m seguridad.login servidor/datos/usuarios.txt <usuario> <perfil>
```

### 2. Levantar la Bóveda y conectar un Custodio

```bash
# Terminal 1: levantar la Bóveda (escucha en 0.0.0.0:7777)
python3 -m servidor.boveda

# Terminal 2 (prueba local en la misma máquina):
python3 -m cliente.custodio 127.0.0.1 7777

# En laboratorio / red (cambiar por la IP de la máquina que corre la Bóveda):
python3 -m cliente.custodio <IP_SERVIDOR> 7777
```

## Pruebas

Para ejecutar todas las pruebas unitarias y de integración:

```bash
python3 -m unittest discover -s pruebas -p "test_*.py" -v
```
