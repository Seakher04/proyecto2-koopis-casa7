# Proyecto 2: Casa 7 (KOOPIS)

Curso: Redes de Comunicación de Datos (CI-0121)  
Universidad de Costa Rica

## Integrantes y reparto
- **Sebastián Sánchez Jiménez (P1)**: capa de red TCP, framing, secuencia y control de conexiones (`red/`, `cliente/custodio.py`).
- **Marina Castro Peralta (P2)**: handshake Diffie-Hellman, cifrado AES-256-CTR y login seguro (`seguridad/handshake.py`, `seguridad/cifrado.py`, `seguridad/login.py`).
- **Hermes Josué Rojas Sancho (P3)**: integridad HMAC-SHA256, comandos y servidor principal de la Bóveda (`seguridad/integridad.py`, `servidor/comandos.py`, `servidor/boveda.py`).

## Estructura

La **Fase 1 (Bóveda KOOPIS)** permanece en los módulos de la raíz para mantener sin cambios los comandos de ejecución y el despliegue de laboratorio; todo el trabajo de **Fase 2 (El Asedio)** vive bajo `fase2/`.

```text
.
├── red/                      # [Fase 1] Capa de red TCP
│   ├── protocolo.py          # Cabecera !IBQ16s, lectura/envío por TCP
│   ├── secuencia.py          # Contadores anti-repetición
│   └── defensa.py            # Límite de conexiones y bitácora de auditoría/alertas
├── seguridad/                # [Fase 1] Criptografía y autenticación
│   ├── handshake.py          # Diffie-Hellman (Grupo 14) y derivación de claves
│   ├── cifrado.py            # Cifrado AES-256-CTR
│   ├── login.py              # Gestión y verificación PBKDF2-HMAC-SHA256
│   └── integridad.py         # Cálculo y verificación HMAC-SHA256
├── servidor/                 # [Fase 1] Bóveda
│   ├── boveda.py             # Servidor TCP concurrente en puerto 7777
│   ├── comandos.py           # Procesamiento de comandos y persistencia JSON
│   └── datos/                # usuarios.txt, boveda.json y alertas_red.log
├── cliente/                  # [Fase 1] Custodio
│   └── custodio.py           # Cliente TCP interactivo
├── pruebas/                  # [Fase 1] Suite unitaria e integración
│   ├── test_framing.py
│   ├── test_seguridad.py
│   ├── test_integridad.py
│   ├── test_comandos.py
│   ├── test_boveda.py
│   └── test_custodio.py
└── fase2/                    # [Fase 2] Defensa de Casa 7 y captura (el ataque a Casa 5 vive en la rama ataqueCasa5)
    ├── README.md             # Guía, checklist y comandos de defensa/captura
    ├── capturar.sh           # Lanza Wireshark (o tcpdump) filtrado para casa7 o casa5
    └── defensa_casa7/        # Herramientas de despliegue, análisis de logs y evidencia/
```

## Requisitos e instalación

Requiere **Python 3** (3.10+) y la dependencia declarada en `requirements.txt`:

```bash
# Opcional (recomendado si el sistema restringe pip global):
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Ejecución

Todos los comandos se ejecutan desde la raíz del repositorio:

### 1. Crear usuarios de la Bóveda

La Bóveda requiere que `servidor/datos/usuarios.txt` exista y tenga al menos un usuario antes de iniciar (el archivo `servidor/datos/boveda.json` se crea automáticamente vacío `{}` si no existe).

Perfiles válidos: `jefe`, `integrante` y `hacinado` (clave de 12 a 128 caracteres, o presionar **Enter** para generar una aleatoria):

```bash
python3 -m seguridad.login servidor/datos/usuarios.txt jefe1 jefe
python3 -m seguridad.login servidor/datos/usuarios.txt custodio1 integrante
python3 -m seguridad.login servidor/datos/usuarios.txt asilo1 hacinado
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

### 3. Flujo de uso en `cliente.custodio`

1. Al conectar, el cliente realiza el **handshake Diffie-Hellman (`0x01`)** de forma automática.
2. Solicita **usuario y clave** (`0x02`, máximo 3 intentos por conexión).
3. Muestra el menú interactivo de comandos (`0x03`):
   - `1. consultar`: solicita la clave a buscar (presionar **Enter** sin texto para listar toda la bóveda).
   - `2. agregar`: solicita clave y valor de texto para guardar o actualizar.
   - `3. borrar`: elimina una clave existente.
   - `4. cierre_emergencia`: pide confirmación (`s/N`), vacía `boveda.json`, cierra todas las conexiones y detiene el servidor.
   - `5. salir`: cierra la sesión del cliente.

**Permisos por perfil:**

| Comando | `jefe` | `integrante` | `hacinado` |
| :--- | :---: | :---: | :---: |
| `consultar` | Sí | Sí | No |
| `agregar` | Sí | Sí | No |
| `borrar` | Sí | No | No |
| `cierre_emergencia` | Sí | No | No |

## Bitácora de auditoría y alertas (Fase 2 / Post-mortem)

La Bóveda escribe en `servidor/datos/alertas_red.log` (con rotación automática a 512 KB y sanitización de texto):
- **`nivel=INFO`**: `conexion_abierta`, `handshake_ok`, `login_ok`, `login_duplicado`, `comando_ok`, `comando_error` (incluye `NO_AUTORIZADO`, `NO_AUTENTICADO`, `SOLICITUD_INVALIDA`, `NO_ENCONTRADO`), `cierre_emergencia` y `conexion_cerrada`. Nunca registra contraseñas ni valores secretos.
- **`nivel=ALERTA`**: `trama_invalida`, `handshake_invalido`, `handshake_duplicado`, `nonce_invalido`, `hmac_invalido`, `formato_invalido`, `credenciales`, `tipo_no_soportado`, `limite_global`, `limite_por_ip` y `excepcion` (con conteo de faltas y bloqueo temporal por IP).

## Pruebas

Para ejecutar la suite completa de pruebas unitarias e integración (52 pruebas):

```bash
python3 -m unittest discover -s pruebas -p "test_*.py" -v
```
